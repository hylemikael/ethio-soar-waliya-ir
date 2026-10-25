"""Unit tests for the streaming EWMA behavioral analytics engine."""

import pytest
from waliya.analytics.ewma_engine import EWMAAnalyticsEngine


class MockRedis:
    """Lightweight in-memory mock of Redis hash and pipeline operations for unit testing."""

    def __init__(self):
        self.hashes = {}

    async def hgetall(self, key: str):
        return dict(self.hashes.get(key, {}))

    async def aclose(self):
        pass

    def pipeline(self):
        pipe = self

        class MockPipe:
            def __init__(self, storage):
                self.storage = storage
                self.actions = []

            def hset(self, key: str, mapping: dict):
                def action():
                    if key not in self.storage:
                        self.storage[key] = {}
                    self.storage[key].update(mapping)
                self.actions.append(action)
                return self

            def expire(self, key: str, ttl: int):
                return self

            async def execute(self):
                for act in self.actions:
                    act()
                return [True] * len(self.actions)

        return MockPipe(self.hashes)


@pytest.mark.asyncio
async def test_ewma_cold_start_suppression():
    """Verify that during cold start (< min_samples), no anomaly is triggered."""
    redis = MockRedis()
    engine = EWMAAnalyticsEngine(
        redis_client=redis,
        alpha=0.2,
        min_samples=5,
        variance_floor=0.25,
        z_threshold=3.0,
    )

    # First 4 samples: stable low values
    for i in range(4):
        anomaly = await engine.evaluate_observation("auth_failure_velocity", "user_1", 1.0)
        assert anomaly is None, f"Expected no anomaly during sample {i+1} of cold start"

    # Even a spike during cold start (sample 5, where prior_count is 4 < min_samples 5) should be suppressed
    anomaly_spike = await engine.evaluate_observation("auth_failure_velocity", "user_1", 100.0)
    assert anomaly_spike is None, "Cold start must suppress alerts when prior samples < 5"


@pytest.mark.asyncio
async def test_ewma_variance_floor_protection():
    """Verify that identical observations do not cause zero-variance division errors."""
    redis = MockRedis()
    engine = EWMAAnalyticsEngine(
        redis_client=redis,
        alpha=0.1,
        min_samples=3,
        variance_floor=0.25,
        z_threshold=3.0,
    )

    # Train with 10 identical observations (variance would normally approach 0)
    for _ in range(10):
        await engine.evaluate_observation("test_metric", "entity_fixed", 5.0)

    # Check that variance is bounded at or above variance_floor
    state = await redis.hgetall("waliya:ewma:test_metric:entity_fixed")
    assert float(state["variance"]) >= 0.25

    # Small elevation should NOT trigger anomaly because variance floor keeps std at least 0.5
    normal_eval = await engine.evaluate_observation("test_metric", "entity_fixed", 6.0)
    assert normal_eval is None


@pytest.mark.asyncio
async def test_ewma_anomaly_detection_and_explanation():
    """Verify that a genuine spike after baseline establishment triggers an explainable anomaly."""
    redis = MockRedis()
    engine = EWMAAnalyticsEngine(
        redis_client=redis,
        alpha=0.1,
        min_samples=5,
        variance_floor=0.25,
        z_threshold=3.0,
    )

    # Establish baseline with 10 typical observations around 2.0
    for _ in range(10):
        await engine.evaluate_observation("auth_failure_velocity", "192.168.1.100", 2.0)

    # Massive spike (e.g. 50 failures)
    anomaly = await engine.evaluate_observation("auth_failure_velocity", "192.168.1.100", 50.0)

    assert anomaly is not None
    assert anomaly.metric_name == "auth_failure_velocity"
    assert anomaly.observed_value == 50.0
    assert anomaly.baseline_mean < 5.0
    assert anomaly.z_score >= 3.0
    assert "exceeds baseline mean" in anomaly.decision_reason
    assert anomaly.threshold == 3.0
