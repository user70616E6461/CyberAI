from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from .config import CyberAIConfig
from .memory import AgentMemory, SharedKnowledgeBase
from .logger import AuditLogger
from rich.console import Console

console = Console()

@dataclass
class Tool:
    name: str
    description: str
    func: Callable
    params: Dict[str, str] = field(default_factory=dict)

class BaseAgent(ABC):
    """
    Abstract base class for all CyberAI agents.
    Each agent: has a role, a tool registry, memory, and access to shared KB.
    """
    AGENT_NAME: str = "base"
    ROLE: str = "Generic Agent"

    def __init__(
        self,
        config: CyberAIConfig,
        kb: SharedKnowledgeBase,
        audit: AuditLogger,
        session_id: str = "unknown"
    ):
        self.config = config
        self.kb = kb
        self.audit = audit
        self.session_id = session_id
        self.memory = AgentMemory(
            max_tokens=config.llm.max_tokens,
            agent_name=self.AGENT_NAME
        )
        self.tools: Dict[str, Tool] = {}
        self._register_tools()

    def register_tool(self, tool: Tool):
        self.tools[tool.name] = tool

    @abstractmethod
    def _register_tools(self):
        """Register agent-specific tools"""
        pass

    @abstractmethod
    def run(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Main agent execution — returns findings dict"""
        pass

    def call_tool(self, tool_name: str, **kwargs) -> Any:
        if tool_name not in self.tools:
            raise ValueError(f"Tool '{tool_name}' not registered in {self.AGENT_NAME}")
        tool = self.tools[tool_name]
        self.audit.agent_action(self.AGENT_NAME, f"calling tool: {tool_name}", kwargs)
        console.print(f"[dim cyan][{self.AGENT_NAME}] → {tool_name}[/dim cyan]")
        result = tool.func(**kwargs)
        return result

    def log(self, msg: str, data: Any = None):
        self.audit.agent_action(self.AGENT_NAME, msg, data)
        console.print(f"[cyan][{self.AGENT_NAME}][/cyan] {msg}")
