"""Analysis pipeline: ingest, scan, correlate."""

from core.pipeline.correlator import CorrelationResult, correlate
from core.pipeline.ingest import IngestResult, ingest_artifact
from core.pipeline.scan import ScanOutcome, run_scan

__all__ = [
    "CorrelationResult",
    "IngestResult",
    "ScanOutcome",
    "correlate",
    "ingest_artifact",
    "run_scan",
]
