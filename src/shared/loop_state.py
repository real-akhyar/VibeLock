"""
VibeLock — Loop State Manager
Reads/writes LOOP-STATE.md. Every cycle starts and ends here.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import re

STATE_FILE = Path(__file__).parent.parent.parent / "LOOP-STATE.md"

@dataclass
class TaskState:
    id: str
    title: str
    status: str  # pending, in-progress, done, blocked
    attempts: int = 0
    last_error: Optional[str] = None

@dataclass
class LoopState:
    phase: str = "INITIAL_BUILD"
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_cycle: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    active_task: Optional[TaskState] = None
    blocked_on: str = ""
    completed: list[str] = field(default_factory=list)
    pending: list[TaskState] = field(default_factory=list)
    
    def load(self) -> "LoopState":
        if not STATE_FILE.exists():
            return self
        content = STATE_FILE.read_text()
        self._parse(content)
        return self
    
    def _parse(self, content: str) -> None:
        phase_m = re.search(r"## Current Phase:\s*(.+)", content)
        if phase_m:
            self.phase = phase_m.group(1).strip()
        
        started_m = re.search(r"## Started:\s*(.+)", content)
        if started_m:
            self.started = started_m.group(1).strip()
        
        last_m = re.search(r"## Last Cycle:\s*(.+)", content)
        if last_m:
            self.last_cycle = last_m.group(1).strip()
        
        blocked_m = re.search(r"### Blocked On\n(.+?)(?=\n###|\Z)", content, re.DOTALL)
        if blocked_m:
            self.blocked_on = blocked_m.group(1).strip().replace("- ", "")
        
        # Parse completed tasks
        completed_section = re.search(r"### Completed Tasks\n(.*?)(?=\n###|\Z)", content, re.DOTALL)
        if completed_section:
            for line in completed_section.group(1).strip().split("\n"):
                line = line.strip("- ").strip()
                if line:
                    self.completed.append(line)
        
        # Parse pending tasks
        pending_section = re.search(r"### Pending Tasks.*?\n(.*?)(?=\n##|\Z)", content, re.DOTALL)
        if pending_section:
            for line in pending_section.group(1).strip().split("\n"):
                line = line.strip("- ").strip()
                if line and line.startswith("VIBE-"):
                    parts = line.split(":", 1)
                    tid = parts[0].strip()
                    title = parts[1].strip() if len(parts) > 1 else ""
                    self.pending.append(TaskState(id=tid, title=title, status="pending"))
    
    def save(self) -> None:
        self.last_cycle = datetime.now(timezone.utc).isoformat()
        lines = [
            "# LOOP-STATE.md — VibeLock Autonomous Engineering State",
            "# Updated every cycle. Read on cold start before doing anything.",
            "",
            f"## Current Phase: {self.phase}",
            f"## Started: {self.started}",
            f"## Last Cycle: {self.last_cycle}",
            "",
            "### Active Task",
        ]
        if self.active_task:
            lines += [
                f"- ID: {self.active_task.id}",
                f"- Title: {self.active_task.title}",
                f"- Status: {self.active_task.status}",
                f"- Attempts: {self.active_task.attempts}",
            ]
            if self.active_task.last_error:
                lines.append(f"- Last Error: {self.active_task.last_error}")
        else:
            lines.append("- None")
        
        lines += [
            "",
            "### Last Attempt",
            "- What: Cycle completed",
            f"- Result: See task status above",
            "- Issues: None",
            "",
            f"### Blocked On\n- {self.blocked_on if self.blocked_on else 'Nothing'}",
            "",
            "### Completed Tasks",
        ]
        for c in self.completed:
            lines.append(f"- {c}")
        
        lines += ["", "### Pending Tasks (ordered)"]
        for p in self.pending:
            lines.append(f"- {p.id}: {p.title}")
        
        STATE_FILE.write_text("\n".join(lines) + "\n")
    
    def mark_done(self, task_id: str) -> None:
        for t in self.pending:
            if t.id == task_id:
                self.completed.append(f"{t.id}: {t.title}")
                self.pending.remove(t)
                break
        self.save()
    
    def next_task(self) -> Optional[TaskState]:
        for t in self.pending:
            if t.status == "pending":
                t.status = "in-progress"
                self.active_task = t
                self.save()
                return t
        return None