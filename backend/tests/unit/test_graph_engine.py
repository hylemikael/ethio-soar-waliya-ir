"""Unit tests for the bounded NetworkX security entity graph engine."""

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest

from waliya.contracts import EntityTypeEnum, GraphSnapshot, RelationTypeEnum
from waliya.correlation.graph_engine import EntityGraphManager


@pytest.mark.asyncio
async def test_repeated_events_do_not_duplicate_nodes_or_edges():
    """Verify that repeated events update existing entities and increment edge weights."""
    manager = EntityGraphManager()
    agent_id = uuid4()

    event = {
        "event_id": str(uuid4()),
        "event_type": "AUTHENTICATION",
        "agent_id": str(agent_id),
        "attributes": {
            "user": "developer",
            "src_ip": "10.0.0.5",
            "status": "SUCCESS",
        },
    }

    # Ingest same event pattern 5 times
    for _ in range(5):
        await manager.ingest_event(event)

    stats = manager.stats()
    # Unique nodes: host:{agent_id}, user:developer, ip:10.0.0.5
    assert stats["node_count"] == 3
    # Unique edges: user -> host, ip -> host
    assert stats["edge_count"] == 2

    # Check edge weight accumulated
    edge_data = manager.graph["user:developer"][f"host:{agent_id}"]
    assert edge_data["weight"] == 5.0
    assert manager.graph.nodes["user:developer"]["observation_count"] == 5


@pytest.mark.asyncio
async def test_multi_event_connected_entity_chain():
    """Demonstrate a multi-event sequence connecting Host, User, Process, File, and IP address."""
    manager = EntityGraphManager()
    agent_id = uuid4()

    # Event 1: User authenticates to Host
    auth_event = {
        "event_id": str(uuid4()),
        "event_type": "AUTHENTICATION",
        "agent_id": str(agent_id),
        "attributes": {"user": "analyst", "service": "ssh", "status": "SUCCESS"},
    }
    await manager.ingest_event(auth_event)

    # Event 2: User spawns Process on Host
    proc_event = {
        "event_id": str(uuid4()),
        "event_type": "PROCESS_EXECUTION",
        "agent_id": str(agent_id),
        "attributes": {"pid": 4010, "exe": "/bin/bash", "username": "analyst", "cmdline": "bash"},
    }
    await manager.ingest_event(proc_event)

    # Event 3: Host modifies File
    fim_event = {
        "event_id": str(uuid4()),
        "event_type": "FILE_INTEGRITY",
        "agent_id": str(agent_id),
        "attributes": {"file_path": "/var/log/audit.log", "action": "MODIFIED"},
    }
    await manager.ingest_event(fim_event)

    # Event 4: Network connection to External IP
    net_event = {
        "event_id": str(uuid4()),
        "event_type": "NETWORK_CONNECTION",
        "agent_id": str(agent_id),
        "attributes": {"src_ip": "10.0.0.100", "dst_ip": "198.51.100.77", "dst_port": 443},
    }
    await manager.ingest_event(net_event)

    # Verify all entities are connected in the graph
    host_id = f"host:{agent_id}"
    user_id = "user:analyst"
    proc_id = f"process:{agent_id}:4010:bash"
    file_id = f"file:{agent_id}:/var/log/audit.log"
    ip_id = "ip:198.51.100.77"

    assert manager.graph.has_node(host_id)
    assert manager.graph.has_node(user_id)
    assert manager.graph.has_node(proc_id)
    assert manager.graph.has_node(file_id)
    assert manager.graph.has_node(ip_id)

    # Check edges
    assert manager.graph.has_edge(user_id, host_id)
    assert manager.graph.has_edge(user_id, proc_id)
    assert manager.graph.has_edge(host_id, proc_id)
    assert manager.graph.has_edge(host_id, file_id)
    assert manager.graph.has_edge(host_id, ip_id)

    # Export subgraph around the central host entity
    subgraph_snapshot = await manager.export_subgraph(center_node_id=host_id, depth=2)
    assert isinstance(subgraph_snapshot, GraphSnapshot)
    node_ids = {n.id for n in subgraph_snapshot.nodes}
    assert host_id in node_ids
    assert user_id in node_ids
    assert proc_id in node_ids
    assert file_id in node_ids
    assert ip_id in node_ids


@pytest.mark.asyncio
async def test_sliding_window_expiration_and_pruning():
    """Verify that edges and orphaned nodes older than retention_seconds are safely pruned."""
    manager = EntityGraphManager(retention_seconds=3600)
    agent_id = uuid4()

    event = {
        "event_id": str(uuid4()),
        "event_type": "AUTHENTICATION",
        "agent_id": str(agent_id),
        "attributes": {"user": "old_user", "status": "FAILURE"},
    }
    await manager.ingest_event(event)

    # Verify initially added
    assert manager.graph.has_node("user:old_user")
    assert manager.graph.has_edge("user:old_user", f"host:{agent_id}")

    # Simulate window expiration by setting retention_seconds to 0
    manager.retention_seconds = 0
    pruned_nodes, pruned_edges = await manager.prune_expired()
    assert pruned_edges >= 1
    # Expired edge removed, orphaned node removed
    assert not manager.graph.has_edge("user:old_user", f"host:{agent_id}")


@pytest.mark.asyncio
async def test_graph_capacity_limits_under_port_scan_burst():
    """Verify that bursty events (e.g. port scan contacting many distinct ports) do not exceed max_edges."""
    manager = EntityGraphManager(max_nodes=50, max_edges=30)
    agent_id = uuid4()

    # Simulate 100 distinct destination connections
    for port in range(1, 101):
        event = {
            "event_id": str(uuid4()),
            "event_type": "NETWORK_CONNECTION",
            "agent_id": str(agent_id),
            "attributes": {"dst_ip": f"192.168.10.{port % 250 + 1}", "dst_port": port},
        }
        await manager.ingest_event(event)

    stats = manager.stats()
    # Edges must be capped at max_edges (30)
    assert stats["edge_count"] <= 30
    # Nodes must be capped at max_nodes (50)
    assert stats["node_count"] <= 50


@pytest.mark.asyncio
async def test_graph_export_schema_validation():
    """Verify that export_snapshot produces valid Pydantic GraphSnapshot schemas."""
    manager = EntityGraphManager()
    agent_id = uuid4()

    event = {
        "event_id": str(uuid4()),
        "event_type": "FILE_INTEGRITY",
        "agent_id": str(agent_id),
        "attributes": {"file_path": "/etc/hosts", "action": "MODIFIED"},
    }
    await manager.ingest_event(event)

    snapshot = await manager.export_snapshot()
    assert isinstance(snapshot, GraphSnapshot)
    assert len(snapshot.nodes) >= 2
    assert len(snapshot.edges) >= 1

    # Verify node fields
    host_node = next(n for n in snapshot.nodes if n.type == EntityTypeEnum.HOST)
    assert host_node.id == f"host:{agent_id}"

    # Verify edge fields
    edge = snapshot.edges[0]
    assert edge.relation == RelationTypeEnum.MODIFIED
    assert edge.weight >= 1.0


@pytest.mark.asyncio
async def test_concurrent_graph_mutations():
    """Verify that concurrent async ingestion tasks do not corrupt graph state."""
    manager = EntityGraphManager()
    agent_id = uuid4()

    async def ingest_task(i: int):
        event = {
            "event_id": str(uuid4()),
            "event_type": "PROCESS_EXECUTION",
            "agent_id": str(agent_id),
            "attributes": {"pid": 1000 + i, "exe": f"/usr/bin/task_{i}", "username": "concurrent_user"},
        }
        await manager.ingest_event(event)

    # Run 25 concurrent tasks
    await asyncio.gather(*[ingest_task(i) for i in range(25)])

    stats = manager.stats()
    # Must have 25 process nodes + 1 host node + 1 user node = 27 nodes
    assert stats["node_count"] == 27
    assert stats["edge_count"] == 50  # 25 host->proc + 25 user->proc
