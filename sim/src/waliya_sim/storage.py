"""Storage and serialization for simulation run reports."""

import json
from pathlib import Path
from typing import List, Optional

from waliya_sim.models import SimulationRunRecord


class ReportStorage:
    """Manages persistence, retrieval, and safe cleanup of simulation run records."""

    def __init__(self, reports_dir: Path):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, run_id: str) -> Path:
        safe_id = "".join(c for c in run_id if c.isalnum() or c in ("-", "_"))
        return self.reports_dir / f"{safe_id}.json"

    def save_report(self, record: SimulationRunRecord) -> Path:
        """Persist simulation record to JSON file, strictly omitting secrets."""
        file_path = self._get_path(record.run_id)
        # Serialize to dict via Pydantic mode='json'
        data = record.model_dump(mode="json")

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)

        return file_path

    def load_report(self, run_id: str) -> Optional[SimulationRunRecord]:
        """Load and reconstruct SimulationRunRecord by run ID."""
        file_path = self._get_path(run_id)
        if not file_path.exists():
            return None

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return SimulationRunRecord.model_validate(data)

    def list_reports(self) -> List[Path]:
        """List all stored simulation run reports."""
        if not self.reports_dir.exists():
            return []
        return sorted(list(self.reports_dir.glob("*.json")), reverse=True)

    def delete_report(self, run_id: str) -> bool:
        """Safely delete a single simulation report file without touching other data."""
        file_path = self._get_path(run_id)
        if file_path.exists():
            file_path.unlink()
            return True
        return False
