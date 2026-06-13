"""
VibeLock — MCP Server (Model Context Protocol)
Provides tools for agents to test code, run scans, and verify patches
during development. Implements the MCP stdio transport for IDE integration.

Tools exposed:
- vibelock_scan_file: Run heuristic scan on a single file
- vibelock_scan_semantic: Run semantic AI scan on a file
- vibelock_verify_patch: Verify a generated patch
- vibelock_sanitize: Sanitize code before LLM dispatch
- vibelock_health: Check VibeLock service health
- vibelock_run_tests: Execute pytest on the test suite
"""

import json
import sys
import asyncio
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.scanner.heuristic import scan_file, Finding, Severity, VulnType
from src.scanner.semantic import scan_code_semantic
from src.verifier.patch_verifier import PatchVerifier
from src.shared.sanitizer import TokenSanitizer

# --- Tool Definitions ---

TOOLS = [
    {
        "name": "vibelock_scan_file",
        "description": "Run heuristic security scan on a file. Detects hardcoded secrets, SQL injection, XSS, and other vulnerabilities using regex/AST patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file to scan"
                },
                "content": {
                    "type": "string",
                    "description": "Optional: file content as string. If not provided, reads from file_path."
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "vibelock_scan_semantic",
        "description": "Run semantic AI scan on a file using DeepSeek-Coder. Detects logic flaws like missing RLS policies, unvalidated inputs, and architectural vulnerabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to scan"
                },
                "content": {
                    "type": "string",
                    "description": "Optional: file content as string"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "vibelock_verify_patch",
        "description": "Verify a generated security patch. Runs syntax check, structural integrity check, and adversarial LLM review.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "original_code": {
                    "type": "string",
                    "description": "Original vulnerable code"
                },
                "patched_code": {
                    "type": "string",
                    "description": "The generated patch code to verify"
                },
                "file_path": {
                    "type": "string",
                    "description": "Path to the file being patched (for language detection)"
                },
                "vulnerability_type": {
                    "type": "string",
                    "description": "Type of vulnerability being fixed (e.g., 'hardcoded_secret', 'sql_injection')"
                }
            },
            "required": ["original_code", "patched_code", "file_path"]
        }
    },
    {
        "name": "vibelock_sanitize",
        "description": "Sanitize code by masking high-entropy strings (passwords, tokens, API keys) before sending to external LLM.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Code to sanitize"
                }
            },
            "required": ["code"]
        }
    },
    {
        "name": "vibelock_health",
        "description": "Check VibeLock service health — verifies all components are operational.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "vibelock_run_tests",
        "description": "Run the VibeLock test suite (pytest). Returns test results summary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "test_path": {
                    "type": "string",
                    "description": "Optional: specific test file or directory to run. Defaults to all tests."
                }
            },
            "required": []
        }
    }
]


# --- Tool Handlers ---

class MCPToolHandler:
    """Handles MCP tool invocations."""

    def __init__(self):
        self.sanitizer = TokenSanitizer()
        self.verifier = PatchVerifier()

    async def handle(self, tool_name: str, arguments: dict) -> dict:
        """Route tool call to the appropriate handler."""
        handlers = {
            "vibelock_scan_file": self._scan_file,
            "vibelock_scan_semantic": self._scan_semantic,
            "vibelock_verify_patch": self._verify_patch,
            "vibelock_sanitize": self._sanitize,
            "vibelock_health": self._health,
            "vibelock_run_tests": self._run_tests,
        }

        handler = handlers.get(tool_name)
        if not handler:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                "isError": True
            }

        try:
            result = await handler(arguments)
            return {
                "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]
            }
        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}")
            return {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True
            }

    async def _scan_file(self, args: dict) -> dict:
        """Run heuristic scan on a file."""
        file_path = Path(args["file_path"])
        content = args.get("content")

        if content is None:
            if not file_path.exists():
                return {"error": f"File not found: {file_path}"}
            content = file_path.read_text(encoding="utf-8", errors="ignore")

        findings = scan_file(file_path, content)

        return {
            "file": str(file_path),
            "findings_count": len(findings),
            "findings": [
                {
                    "type": f.vulnerability_type.value,
                    "severity": f.severity.value,
                    "line": f.line_number,
                    "description": f.description,
                    "snippet": f.code_snippet[:150],
                    "remediation": f.remediation_hint,
                }
                for f in findings
            ]
        }

    async def _scan_semantic(self, args: dict) -> dict:
        """Run semantic AI scan on a file."""
        file_path = Path(args["file_path"])
        content = args.get("content")

        if content is None:
            if not file_path.exists():
                return {"error": f"File not found: {file_path}"}
            content = file_path.read_text(encoding="utf-8", errors="ignore")

        # Sanitize before sending to LLM
        clean_code = self.sanitizer.sanitize(content)
        findings = await scan_code_semantic(clean_code, str(file_path))

        return {
            "file": str(file_path),
            "findings_count": len(findings),
            "findings": [
                {
                    "type": f.get("type", "unknown"),
                    "severity": f.get("severity", "medium"),
                    "line": f.get("line_number"),
                    "description": f.get("description", ""),
                    "confidence": f.get("confidence", 0.0),
                }
                for f in findings
            ]
        }

    async def _verify_patch(self, args: dict) -> dict:
        """Verify a generated patch."""
        original = args["original_code"]
        patched = args["patched_code"]
        file_path = args["file_path"]
        vuln_type = args.get("vulnerability_type", "unknown")

        result = self.verifier.verify(
            original_code=original,
            patched_code=patched,
            file_path=file_path,
            vulnerability={"vulnerability_type": vuln_type},
        )

        return {
            "passed": result.get("passed", False),
            "checks": result.get("checks", {}),
            "errors": result.get("errors", []),
            "warnings": result.get("warnings", []),
            "summary": result.get("summary", ""),
        }

    async def _sanitize(self, args: dict) -> dict:
        """Sanitize code before LLM dispatch."""
        code = args["code"]
        sanitized = self.sanitizer.sanitize(code)
        redactions = self.sanitizer.get_redaction_count()

        return {
            "original_length": len(code),
            "sanitized_length": len(sanitized),
            "redactions": redactions,
            "sanitized": sanitized[:500] + ("..." if len(sanitized) > 500 else ""),
        }

    async def _health(self, args: dict) -> dict:
        """Check VibeLock service health."""
        import time
        import os

        checks = {}

        # Check scanner
        try:
            from src.scanner.heuristic import scan_file
            checks["heuristic_scanner"] = "ok"
        except Exception as e:
            checks["heuristic_scanner"] = f"error: {e}"

        # Check semantic scanner
        try:
            from src.scanner.semantic import scan_code_semantic
            checks["semantic_scanner"] = "ok"
        except Exception as e:
            checks["semantic_scanner"] = f"error: {e}"

        # Check verifier
        try:
            from src.verifier.patch_verifier import PatchVerifier
            checks["verifier"] = "ok"
        except Exception as e:
            checks["verifier"] = f"error: {e}"

        # Check sanitizer
        try:
            from src.shared.sanitizer import TokenSanitizer
            checks["sanitizer"] = "ok"
        except Exception as e:
            checks["sanitizer"] = f"error: {e}"

        # Check Supabase
        try:
            from src.shared.supabase_client import supabase
            checks["supabase"] = supabase.health_check()
        except Exception as e:
            checks["supabase"] = {"connected": False, "error": str(e)}

        # Check Redis
        redis_ok = False
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
            await r.ping()
            redis_ok = True
            await r.close()
        except Exception:
            pass
        checks["redis"] = "connected" if redis_ok else "not_available"

        all_ok = all(
            v == "ok" or (isinstance(v, dict) and v.get("connected", False))
            for v in checks.values()
        )

        return {
            "status": "healthy" if all_ok else "degraded",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "components": checks,
        }

    async def _run_tests(self, args: dict) -> dict:
        """Run pytest on the VibeLock test suite."""
        import subprocess
        import os

        test_path = args.get("test_path", "tests/")
        workspace = Path(__file__).resolve().parent.parent.parent

        cmd = ["python", "-m", "pytest", test_path, "-v", "--tb=short"]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=120,
                env={**os.environ, "PYTHONPATH": str(workspace)},
            )

            return {
                "exit_code": result.returncode,
                "passed": result.returncode == 0,
                "stdout": result.stdout[-3000:],
                "stderr": result.stderr[-1000:] if result.stderr else "",
            }
        except subprocess.TimeoutExpired:
            return {"error": "Test run timed out after 120 seconds"}
        except Exception as e:
            return {"error": str(e)}


# --- MCP Protocol Implementation ---

class MCPServer:
    """
    Model Context Protocol server using stdio transport.
    Compatible with Claude Desktop, Continue.dev, and other MCP clients.
    """

    def __init__(self):
        self.handler = MCPToolHandler()
        self._initialized = False

    async def run(self):
        """Run the MCP server on stdio."""
        logger.info("VibeLock MCP Server starting on stdio")

        # Read from stdin, write to stdout
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        writer = asyncio.StreamWriter(writer_transport, writer_protocol, reader, asyncio.get_event_loop())

        while True:
            try:
                line = await reader.readline()
                if not line:
                    break

                message = json.loads(line.decode())
                response = await self._process_message(message)

                response_bytes = (json.dumps(response) + "\n").encode()
                writer.write(response_bytes)
                await writer.drain()

            except json.JSONDecodeError:
                error_resp = json.dumps({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None
                }) + "\n"
                writer.write(error_resp.encode())
                await writer.drain()
            except Exception as e:
                logger.error(f"MCP message processing failed: {e}")

    async def _process_message(self, message: dict) -> dict:
        """Process an MCP JSON-RPC message."""
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params", {})

        if method == "initialize":
            return self._handle_initialize(msg_id, params)
        elif method == "initialized":
            self._initialized = True
            return {}
        elif method == "tools/list":
            return self._handle_list_tools(msg_id)
        elif method == "tools/call":
            return await self._handle_call_tool(msg_id, params)
        elif method == "shutdown":
            return self._handle_shutdown(msg_id)
        else:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Method not found: {method}"},
                "id": msg_id
            }

    def _handle_initialize(self, msg_id, params: dict) -> dict:
        """Handle MCP initialize request."""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "vibelock-mcp",
                    "version": "0.2.0"
                }
            }
        }

    def _handle_list_tools(self, msg_id) -> dict:
        """Handle MCP tools/list request."""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": TOOLS
            }
        }

    async def _handle_call_tool(self, msg_id, params: dict) -> dict:
        """Handle MCP tools/call request."""
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        result = await self.handler.handle(tool_name, arguments)

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result
        }

    def _handle_shutdown(self, msg_id) -> dict:
        """Handle MCP shutdown request."""
        logger.info("VibeLock MCP Server shutting down")
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {}
        }


# --- Entry Point ---

def main():
    """Entry point for `vibelock-mcp` command."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,  # stderr so stdout stays clean for MCP protocol
    )

    server = MCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()