"""
VibeLock — Budget Guardrails
Enforces per-cycle and per-day token/cost caps.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import json

BUDGET_FILE = Path(__file__).parent.parent / "tooling" / "budget_state.json"

@dataclass
class BudgetTracker:
    daily_cap_tokens: int = 1_000_000  # 1M tokens/day
    cycle_cap_tokens: int = 50_000      # 50K tokens/cycle
    daily_used: int = 0
    cycle_used: int = 0
    last_reset: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def load(self) -> "BudgetTracker":
        if BUDGET_FILE.exists():
            data = json.loads(BUDGET_FILE.read_text())
            self.daily_used = data.get("daily_used", 0)
            self.cycle_used = data.get("cycle_used", 0)
            self.last_reset = data.get("last_reset", datetime.utcnow().isoformat())
            # Reset daily if it's a new day
            last = datetime.fromisoformat(self.last_reset)
            if datetime.utcnow() - last > timedelta(hours=24):
                self.daily_used = 0
                self.last_reset = datetime.utcnow().isoformat()
        return self
    
    def save(self) -> None:
        BUDGET_FILE.parent.mkdir(parents=True, exist_ok=True)
        BUDGET_FILE.write_text(json.dumps({
            "daily_used": self.daily_used,
            "cycle_used": self.cycle_used,
            "last_reset": self.last_reset,
        }, indent=2))
    
    def can_proceed(self, estimated_tokens: int) -> bool:
        if self.daily_used + estimated_tokens > self.daily_cap_tokens:
            return False
        if self.cycle_used + estimated_tokens > self.cycle_cap_tokens:
            return False
        return True
    
    def record_usage(self, tokens: int) -> None:
        self.daily_used += tokens
        self.cycle_used += tokens
        self.save()
    
    def reset_cycle(self) -> None:
        self.cycle_used = 0
        self.save()