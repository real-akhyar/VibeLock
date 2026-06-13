"""Tests for VibeLock loop state manager."""
import tempfile
from pathlib import Path

import pytest

from src.shared.loop_state import LoopState, TaskState, STATE_FILE


class TestLoopState:
    def test_loads_fresh_state_when_no_file(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setattr(
                "src.shared.loop_state.STATE_FILE",
                Path(tmp) / "LOOP-STATE.md",
            )
            state = LoopState().load()
            assert state.phase == "INITIAL_BUILD"
            assert state.pending == []

    def test_save_and_reload(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setattr(
                "src.shared.loop_state.STATE_FILE",
                Path(tmp) / "LOOP-STATE.md",
            )
            state = LoopState()
            state.pending = [
                TaskState(id="VIBE-001", title="Test task", status="pending"),
                TaskState(id="VIBE-002", title="Another task", status="pending"),
            ]
            state.completed = ["VIBE-000: Scaffolding"]
            state.save()
            
            loaded = LoopState().load()
            assert len(loaded.pending) == 2
            assert loaded.pending[0].id == "VIBE-001"
            assert len(loaded.completed) == 1

    def test_mark_done(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setattr(
                "src.shared.loop_state.STATE_FILE",
                Path(tmp) / "LOOP-STATE.md",
            )
            state = LoopState()
            state.pending = [
                TaskState(id="VIBE-001", title="Test task", status="pending"),
            ]
            state.save()
            
            state.mark_done("VIBE-001")
            assert len(state.pending) == 0
            assert len(state.completed) == 1

    def test_next_task(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setattr(
                "src.shared.loop_state.STATE_FILE",
                Path(tmp) / "LOOP-STATE.md",
            )
            state = LoopState()
            state.pending = [
                TaskState(id="VIBE-001", title="First", status="pending"),
                TaskState(id="VIBE-002", title="Second", status="pending"),
            ]
            
            next_t = state.next_task()
            assert next_t.id == "VIBE-001"
            assert next_t.status == "in-progress"
            assert state.active_task == next_t