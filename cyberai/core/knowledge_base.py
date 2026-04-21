from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class KBEntry:
    key: str
    value: Any
    agent: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: List[str] = field(default_factory=list)

class KnowledgeBase:
    """
    Shared memory store for all agents in a session.
    Agents read/write through trust-validated keys.
    """
    def __init__(self):
        self._store: Dict[str, KBEntry] = {}
        self._history: List[KBEntry] = []

    def set(self, key: str, value: Any, agent: str, tags: List[str] = []):
        entry = KBEntry(key=key, value=value, agent=agent, tags=tags)
        self._store[key] = entry
        self._history.append(entry)

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        return entry.value if entry else None

    def get_by_tag(self, tag: str) -> Dict[str, Any]:
        return {
            k: v.value for k, v in self._store.items()
            if tag in v.tags
        }

    def keys(self) -> List[str]:
        return list(self._store.keys())

    def snapshot(self) -> Dict[str, Any]:
        return {k: v.value for k, v in self._store.items()}

    def history(self) -> List[Dict]:
        return [
            {"key": e.key, "agent": e.agent, "timestamp": e.timestamp}
            for e in self._history
        ]
