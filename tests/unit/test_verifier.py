"""Tests for VibeLock verifier."""
import tempfile
from pathlib import Path

import pytest

from src.verifier.patch_verifier import (
    verify_patch_syntax,
    verify_patch_applies,
    verify_patch,
)


class TestSyntaxVerification:
    async def test_valid_python_passes(self):
        ok, msg = await verify_patch_syntax(Path("test.py"), "x = 1\ny = 2")
        assert ok

    async def test_invalid_python_fails(self):
        ok, msg = await verify_patch_syntax(Path("test.py"), "x = \nif True")
        assert not ok

    async def test_empty_patch_fails(self):
        ok, msg = await verify_patch_syntax(Path("test.py"), "")
        assert not ok


class TestPatchApplication:
    async def test_valid_patch_applies(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1\ny = 2\n")
            tmp_path = Path(f.name)
        
        try:
            ok, msg = await verify_patch_applies(tmp_path, "z = 3")
            assert ok
        finally:
            tmp_path.unlink()

    async def test_broken_patch_fails(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1\n")
            tmp_path = Path(f.name)
        
        try:
            ok, msg = await verify_patch_applies(tmp_path, "x = \nif")
            assert not ok
        finally:
            tmp_path.unlink()


class TestFullVerification:
    async def test_clean_patch_passes_all(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1\n")
            tmp_path = Path(f.name)
        
        try:
            ok, msg = await verify_patch(tmp_path, "y = 2", run_linter=False)
            assert ok
        finally:
            tmp_path.unlink()

    async def test_broken_patch_fails(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1\n")
            tmp_path = Path(f.name)
        
        try:
            ok, msg = await verify_patch(tmp_path, "x = \nif True:", run_linter=False)
            assert not ok
        finally:
            tmp_path.unlink()