"""
External Command Runner - Async wrapper for system tools.
Provides safe, timeout-controlled execution of external security tools.
"""

import asyncio
import logging
import shutil
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result from an external command execution."""

    success: bool
    stdout: str
    stderr: str
    return_code: int
    command: str
    duration: float
    tool_available: bool = True


class ExternalCommandRunner:
    """
    Async wrapper for executing external security tools.
    Supports: nmap, nikto, gobuster, john, hashcat, etc.
    """

    # Known security tools and their binary names
    KNOWN_TOOLS = {
        "nmap": ["nmap"],
        "nikto": ["nikto", "nikto.pl"],
        "gobuster": ["gobuster"],
        "dirb": ["dirb"],
        "john": ["john", "john-the-ripper"],
        "hashcat": ["hashcat"],
        "sqlmap": ["sqlmap"],
        "wfuzz": ["wfuzz"],
        "ffuf": ["ffuf"],
        "nuclei": ["nuclei"],
        "subfinder": ["subfinder"],
        "amass": ["amass"],
        "masscan": ["masscan"],
        "whatweb": ["whatweb"],
        "wpscan": ["wpscan"],
        "hydra": ["hydra"],
        "medusa": ["medusa"],
        "cewl": ["cewl"],
        "crunch": ["crunch"],
    }

    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self._tool_cache: dict[str, str | None] = {}

    def check_tool_available(self, tool_name: str) -> str | None:
        """Check if a tool is available in PATH. Returns path or None."""
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]

        binaries = self.KNOWN_TOOLS.get(tool_name, [tool_name])

        for binary in binaries:
            path = shutil.which(binary)
            if path:
                self._tool_cache[tool_name] = path
                logger.debug(f"Found {tool_name} at {path}")
                return path

        self._tool_cache[tool_name] = None
        logger.warning(f"Tool '{tool_name}' not found in PATH")
        return None

    def get_available_tools(self) -> dict[str, bool]:
        """Return availability status of all known tools."""
        return {tool: self.check_tool_available(tool) is not None for tool in self.KNOWN_TOOLS}

    async def run_command(
        self,
        command: list[str],
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stdin_data: str | None = None,
    ) -> CommandResult:
        """
        Execute an external command asynchronously.

        Args:
            command: Command and arguments as list
            timeout: Override default timeout
            cwd: Working directory
            env: Environment variables
            stdin_data: Data to send to stdin

        Returns:
            CommandResult with stdout, stderr, return code
        """
        import os
        import time

        timeout = timeout or self.timeout
        cmd_str = " ".join(command)
        start_time = time.time()

        # Merge environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                cwd=cwd,
                env=run_env,
            )

            stdin_bytes = stdin_data.encode() if stdin_data else None
            stdout, stderr = await asyncio.wait_for(process.communicate(input=stdin_bytes), timeout=timeout)

            duration = time.time() - start_time

            return CommandResult(
                success=process.returncode == 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                return_code=process.returncode or 0,
                command=cmd_str,
                duration=duration,
            )

        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            duration = time.time() - start_time
            return CommandResult(
                success=False,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                return_code=-1,
                command=cmd_str,
                duration=duration,
            )
        except FileNotFoundError:
            duration = time.time() - start_time
            return CommandResult(
                success=False,
                stdout="",
                stderr=f"Command not found: {command[0]}",
                return_code=-1,
                command=cmd_str,
                duration=duration,
                tool_available=False,
            )
        except Exception as e:
            duration = time.time() - start_time
            logger.exception(f"Command execution failed: {e}")
            return CommandResult(
                success=False, stdout="", stderr=str(e), return_code=-1, command=cmd_str, duration=duration
            )

    async def run_tool(self, tool_name: str, args: list[str], **kwargs) -> CommandResult:
        """
        Run a known security tool with arguments.
        Automatically finds the tool binary.
        """
        tool_path = self.check_tool_available(tool_name)

        if not tool_path:
            return CommandResult(
                success=False,
                stdout="",
                stderr=f"Tool '{tool_name}' is not installed or not in PATH",
                return_code=-1,
                command=f"{tool_name} {' '.join(args)}",
                duration=0,
                tool_available=False,
            )

        command = [tool_path] + args
        return await self.run_command(command, **kwargs)


class StreamingCommandRunner(ExternalCommandRunner):
    """
    Extended runner with real-time output streaming support.
    Useful for long-running scans with progress updates.
    """

    async def run_streaming(
        self, command: list[str], output_callback: callable, timeout: int | None = None, cwd: str | None = None
    ) -> CommandResult:
        """
        Run command with real-time output streaming.

        Args:
            command: Command and arguments
            output_callback: Async callback(line: str, is_stderr: bool)
            timeout: Command timeout
            cwd: Working directory
        """
        import time

        timeout = timeout or self.timeout
        cmd_str = " ".join(command)
        start_time = time.time()

        stdout_lines = []
        stderr_lines = []

        try:
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=cwd
            )

            async def read_stream(stream, is_stderr: bool):
                lines = stderr_lines if is_stderr else stdout_lines
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    lines.append(decoded)
                    if output_callback:
                        await output_callback(decoded, is_stderr)

            await asyncio.wait_for(
                asyncio.gather(read_stream(process.stdout, False), read_stream(process.stderr, True)), timeout=timeout
            )

            await process.wait()
            duration = time.time() - start_time

            return CommandResult(
                success=process.returncode == 0,
                stdout="\n".join(stdout_lines),
                stderr="\n".join(stderr_lines),
                return_code=process.returncode or 0,
                command=cmd_str,
                duration=duration,
            )

        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            duration = time.time() - start_time
            return CommandResult(
                success=False,
                stdout="\n".join(stdout_lines),
                stderr=f"Timeout after {timeout}s\n" + "\n".join(stderr_lines),
                return_code=-1,
                command=cmd_str,
                duration=duration,
            )
        except Exception as e:
            duration = time.time() - start_time
            return CommandResult(
                success=False,
                stdout="\n".join(stdout_lines),
                stderr=str(e),
                return_code=-1,
                command=cmd_str,
                duration=duration,
            )
