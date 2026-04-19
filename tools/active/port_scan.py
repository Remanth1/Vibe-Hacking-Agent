"""
Port scanning wrapper (active tool).
Wraps nmap with hard restrictions:
- Only allowed when scope.active_testing == True
- Limited to a safe set of nmap flags (no OS detection, no scripts, no aggressive scan)
- Honours the intensity setting to control timing template
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List

# Intensity → nmap timing template  (-T0 slowest … -T5 insane)
_INTENSITY_TIMING = {"low": "-T2", "medium": "-T3", "high": "-T4"}

# Top ports to scan per intensity level (nmap --top-ports)
_INTENSITY_TOP_PORTS = {"low": "100", "medium": "500", "high": "1000"}

# Hard limit on allowed nmap flags (do NOT allow -O, --script, -A, etc.)
_SAFE_FLAGS = {"-sV", "--version-intensity", "-p", "--top-ports", "-T2", "-T3", "-T4", "--open"}


def run_port_scan(
    target: str,
    intensity: str = "low",
    port_range: str = "",
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Run a restricted nmap scan against *target*.

    Returns::

        {
            "command": "nmap ...",
            "output": "<raw nmap text>",
            "open_ports": [{"port": 80, "service": "http", "version": "..."}],
            "error": None | "error message",
        }
    """
    result: Dict[str, Any] = {
        "command": "",
        "output": "",
        "open_ports": [],
        "error": None,
    }

    if not shutil.which("nmap"):
        result["error"] = (
            "nmap is not installed or not in PATH.  "
            "Install it with: apt-get install nmap  (or brew install nmap on macOS)"
        )
        return result

    timing = _INTENSITY_TIMING.get(intensity, "-T2")
    top_ports = _INTENSITY_TOP_PORTS.get(intensity, "100")

    cmd: List[str] = ["nmap", "-sV", "--version-intensity", "3", timing, "--open"]
    if port_range:
        cmd += ["-p", port_range]
    else:
        cmd += ["--top-ports", top_ports]
    cmd.append(target)

    result["command"] = " ".join(cmd)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result["output"] = proc.stdout + proc.stderr
        result["open_ports"] = _parse_nmap_output(proc.stdout)
    except subprocess.TimeoutExpired:
        result["error"] = f"nmap scan timed out after {timeout}s"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def _parse_nmap_output(text: str) -> List[Dict[str, Any]]:
    """Extract open port information from nmap plain-text output."""
    import re

    ports: List[Dict[str, Any]] = []
    # Example line: "80/tcp   open  http    Apache httpd 2.4.41"
    pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", re.MULTILINE
    )
    for match in pattern.finditer(text):
        ports.append(
            {
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "service": match.group(3),
                "version": match.group(4).strip(),
            }
        )
    return ports
