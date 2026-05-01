"""
ScanSession — full lifecycle manager for a pentest scan.
Ties together: ReconAgent → IntelAgent → ExploitAgent → ReportAgent
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class ScanState(str, Enum):
    CREATED    = "created"
    RUNNING    = "running"
    RECON      = "recon"
    INTEL      = "intel"
    EXPLOIT    = "exploit"
    REPORT     = "report"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"


class ScanPhase(str, Enum):
    RECON   = "recon"
    INTEL   = "intel"
    EXPLOIT = "exploit"
    REPORT  = "report"


@dataclass
class PhaseResult:
    phase:      ScanPhase
    success:    bool
    started_at: str
    ended_at:   str
    duration_s: float
    data:       Dict[str, Any] = field(default_factory=dict)
    error:      Optional[str]  = None


@dataclass
class ScanSession:
    target:     str
    session_id: str                  = field(default_factory=lambda: str(uuid.uuid4())[:8])
    state:      ScanState            = ScanState.CREATED
    created_at: str                  = field(default_factory=lambda: _now())
    started_at: Optional[str]        = None
    ended_at:   Optional[str]        = None
    phases:     List[PhaseResult]    = field(default_factory=list)
    kb:         Dict[str, Any]       = field(default_factory=dict)
    errors:     List[str]            = field(default_factory=list)
    authorized_scope: List[str]      = field(default_factory=list)

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> None:
        self.state      = ScanState.RUNNING
        self.started_at = _now()

    def complete(self) -> None:
        self.state    = ScanState.COMPLETED
        self.ended_at = _now()

    def fail(self, reason: str) -> None:
        self.state    = ScanState.FAILED
        self.ended_at = _now()
        self.errors.append(reason)

    def cancel(self) -> None:
        self.state    = ScanState.CANCELLED
        self.ended_at = _now()

    def set_phase(self, phase: ScanPhase) -> None:
        self.state = ScanState(phase.value)

    # ── phase tracking ────────────────────────────────────────────────

    def record_phase(
        self,
        phase:    ScanPhase,
        success:  bool,
        started:  str,
        data:     Dict[str, Any] = None,
        error:    str = None,
    ) -> PhaseResult:
        ended = _now()
        duration = _delta(started, ended)
        result = PhaseResult(
            phase      = phase,
            success    = success,
            started_at = started,
            ended_at   = ended,
            duration_s = duration,
            data       = data or {},
            error      = error,
        )
        self.phases.append(result)
        return result

    # ── kb helpers ────────────────────────────────────────────────────

    def kb_set(self, key: str, value: Any) -> None:
        self.kb[key] = value

    def kb_get(self, key: str, default: Any = None) -> Any:
        return self.kb.get(key, default)

    # ── summary ───────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        duration = None
        if self.started_at and self.ended_at:
            duration = round(_delta(self.started_at, self.ended_at), 1)
        return {
            "session_id":  self.session_id,
            "target":      self.target,
            "state":       self.state.value,
            "created_at":  self.created_at,
            "started_at":  self.started_at,
            "ended_at":    self.ended_at,
            "duration_s":  duration,
            "phases":      [_phase_summary(p) for p in self.phases],
            "errors":      self.errors,
            "kb_keys":     list(self.kb.keys()),
        }

    def __repr__(self) -> str:
        return (
            f"ScanSession(id={self.session_id}, "
            f"target={self.target}, state={self.state.value})"
        )


# ── helpers ───────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _delta(start: str, end: str) -> float:
    try:
        t0 = datetime.fromisoformat(start)
        t1 = datetime.fromisoformat(end)
        return (t1 - t0).total_seconds()
    except Exception:
        return 0.0


def _phase_summary(p: PhaseResult) -> Dict[str, Any]:
    return {
        "phase":      p.phase.value,
        "success":    p.success,
        "duration_s": p.duration_s,
        "error":      p.error,
    }
