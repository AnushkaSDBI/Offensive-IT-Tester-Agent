"""Core, security-critical logic: authorization, audit, detection, recon, and targets."""
from .scope import ScopeDefinition, ScopeGate, default_scope
from .audit import AuditLog
from .detectors import (
    SQLiDetector, XSSDetector, CSRFDetector, SSRFDetector, CmdInjDetector,
    build_detectors,
    IndirectRAGPoisoningDetector, MCPToolPoisoningDetector, build_detectors_extended,
)
from .target import MockTarget
from .recon import crawl_surfaces

__all__ = [
    "ScopeDefinition", "ScopeGate", "default_scope",
    "AuditLog",
    "SQLiDetector", "XSSDetector", "CSRFDetector", "SSRFDetector", "CmdInjDetector",
    "build_detectors",
    "IndirectRAGPoisoningDetector", "MCPToolPoisoningDetector", "build_detectors_extended",
    "MockTarget",
    "crawl_surfaces",
]
