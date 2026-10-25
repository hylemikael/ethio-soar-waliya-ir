"""Correlation graph API endpoints."""

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from waliya.contracts import (
    AttackPath,
    CorrelationPathResponse,
    EntityNeighborsResponse,
    GraphNode,
    GraphSnapshot,
)
from waliya.core.auth import verify_admin_key
from waliya.correlation.graph_engine import get_graph_manager

logger = logging.getLogger("waliya.api.routes.correlation")

router = APIRouter(prefix="/correlation", tags=["correlation"])


@router.get(
    "/graph",
    response_model=GraphSnapshot,
    status_code=status.HTTP_200_OK,
    summary="Export bounded entity correlation graph snapshot",
)
async def get_graph_snapshot(
    max_nodes: int = Query(default=200, ge=1, le=1000),
    max_edges: int = Query(default=500, ge=1, le=2000),
    center_node: Optional[str] = Query(default=None, description="Optional entity node ID to extract ego subgraph around"),
    depth: int = Query(default=2, ge=1, le=5),
    _admin: str = Depends(verify_admin_key),
) -> GraphSnapshot:
    """Export the active in-memory entity correlation graph or a specific entity subgraph."""
    graph_manager = get_graph_manager()
    if center_node:
        snapshot = await graph_manager.export_subgraph(center_node, depth=depth, max_nodes=max_nodes, max_edges=max_edges)
    else:
        snapshot = await graph_manager.export_snapshot(max_nodes=max_nodes, max_edges=max_edges)

    return snapshot


@router.get(
    "/attack-paths",
    response_model=List[AttackPath],
    status_code=status.HTTP_200_OK,
    summary="Compute global bounded attack paths across the active correlation graph",
)
async def get_correlation_attack_paths(
    max_depth: int = Query(default=4, ge=1, le=6),
    max_paths: int = Query(default=10, ge=1, le=20),
    _admin: str = Depends(verify_admin_key),
) -> List[AttackPath]:
    """Discover directed attack progressions connecting entry nodes to impacted assets."""
    graph_manager = get_graph_manager()
    return await graph_manager.find_attack_paths(max_depth=max_depth, max_paths=max_paths)


@router.get(
    "/paths",
    response_model=CorrelationPathResponse,
    status_code=status.HTTP_200_OK,
    summary="Find simple directed attack paths between two specific entities",
)
async def get_paths_between_entities(
    source: str = Query(..., min_length=1, max_length=255, description="Source entity ID"),
    target: str = Query(..., min_length=1, max_length=255, description="Target entity ID"),
    max_depth: int = Query(default=4, ge=1, le=6),
    limit: int = Query(default=5, ge=1, le=20),
    _admin: str = Depends(verify_admin_key),
) -> CorrelationPathResponse:
    """Find simple paths connecting a source entity to a target entity within bounded depth."""
    graph_manager = get_graph_manager()
    paths = await graph_manager.find_paths_between(
        source_id=source,
        target_id=target,
        max_depth=max_depth,
        max_paths=limit,
    )
    return CorrelationPathResponse(
        source=source,
        target=target,
        paths=paths,
        total_paths_found=len(paths),
    )


@router.get(
    "/entities/{entity_id}/neighbors",
    response_model=EntityNeighborsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get bounded k-hop neighborhood around an entity",
)
async def get_entity_neighbors(
    entity_id: str,
    depth: int = Query(default=1, ge=1, le=4),
    max_neighbors: int = Query(default=50, ge=1, le=200),
    _admin: str = Depends(verify_admin_key),
) -> EntityNeighborsResponse:
    """Return an entity's 1-hop or k-hop neighborhood with supporting edges and degrees."""
    graph_manager = get_graph_manager()
    res = await graph_manager.get_entity_neighbors(
        entity_id=entity_id,
        depth=depth,
        max_neighbors=max_neighbors,
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entity '{entity_id}' not found in active correlation graph",
        )
    return res


@router.get(
    "/entities/{entity_id}",
    response_model=GraphNode,
    status_code=status.HTTP_200_OK,
    summary="Get details for a specific entity node",
)
async def get_entity_node(
    entity_id: str,
    _admin: str = Depends(verify_admin_key),
) -> GraphNode:
    """Retrieve metadata, timestamps, and observation count for a specific entity."""
    graph_manager = get_graph_manager()
    if not graph_manager.graph.has_node(entity_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entity '{entity_id}' not found in active correlation graph",
        )
    data = graph_manager.graph.nodes[entity_id]
    return GraphNode(
        id=entity_id,
        type=data.get("entity_type", "Host"),
        label=data.get("label", entity_id),
        properties=data.get("properties", {}),
        first_seen=data.get("first_seen"),
        last_seen=data.get("last_seen"),
        observation_count=data.get("observation_count", 1),
    )


@router.get(
    "/stats",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get correlation graph statistics",
)
async def get_graph_stats(
    _admin: str = Depends(verify_admin_key),
) -> Dict[str, Any]:
    """Return structural node and edge counts and memory boundaries for the entity graph."""
    graph_manager = get_graph_manager()
    return graph_manager.stats()


@router.post(
    "/prune",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Trigger immediate graph pruning of expired entities and relationships",
)
async def trigger_graph_prune(
    _admin: str = Depends(verify_admin_key),
) -> Dict[str, Any]:
    """Manually invoke sliding-window retention pruning on the entity graph."""
    graph_manager = get_graph_manager()
    pruned_nodes, pruned_edges = await graph_manager.prune_expired()
    return {
        "status": "COMPLETED",
        "pruned_nodes": pruned_nodes,
        "pruned_edges": pruned_edges,
        "remaining_stats": graph_manager.stats(),
    }
