"""Tests for VibeLock budget tracker."""
import tempfile
from pathlib import Path

import pytest

from src.shared.budget import BudgetTracker, BUDGET_FILE


class TestBudgetTracker:
    def test_can_proceed_under_cap(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setattr(
                "src.shared.budget.BUDGET_FILE",
                Path(tmp) / "budget_state.json",
            )
            tracker = BudgetTracker().load()
            assert tracker.can_proceed(10_000)

    def test_blocks_when_over_cycle_cap(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setattr(
                "src.shared.budget.BUDGET_FILE",
                Path(tmp) / "budget_state.json",
            )
            tracker = BudgetTracker().load()
            tracker.cycle_used = 49_000
            assert not tracker.can_proceed(2_000)

    def test_blocks_when_over_daily_cap(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setattr(
                "src.shared.budget.BUDGET_FILE",
                Path(tmp) / "budget_state.json",
            )
            tracker = BudgetTracker().load()
            tracker.daily_used = 999_000
            assert not tracker.can_proceed(2_000)

    def test_record_usage_and_reset_cycle(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setattr(
                "src.shared.budget.BUDGET_FILE",
                Path(tmp) / "budget_state.json",
            )
            tracker = BudgetTracker().load()
            tracker.record_usage(10_000)
            assert tracker.cycle_used == 10_000
            tracker.reset_cycle()
            assert tracker.cycle_used == 0

    def test_persists_state(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setattr(
                "src.shared.budget.BUDGET_FILE",
                Path(tmp) / "budget_state.json",
            )
            tracker = BudgetTracker().load()
            tracker.record_usage(5_000)
            
            loaded = BudgetTracker().load()
            assert loaded.daily_used == 5_000