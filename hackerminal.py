#!/usr/bin/env python3
"""
HackerTerminal — btop-for-hackers TUI Dashboard

Features:
  CPU/RAM bar gauges with sparkline history
  Network bandwidth monitor (real-time per interface)
  WiFi device enumeration (scapy)
  Open port scanner (local)
  Running service display (psutil)
  Docker container overview (docker SDK via subprocess)
  Active SSH session watcher
  VPN tunnel detection (pyroute2)
  GPU monitor (nvidia-smi fallback)

Libraries:  rich  |  textual  |  psutil  |  scapy  |  pyroute2  |  speedtest-cli
"""

from __future__ import annotations

import asyncio
import os
import re
import socket
import subprocess
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil
from rich.align import Align
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

# ---------------------------------------------------------------------------
# Textual imports
# ---------------------------------------------------------------------------
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import (
    Button,
    Footer,
    Header,
    Label,
    ListItem,
    ListView,
    Static,
)

# ---------------------------------------------------------------------------
# Optional imports (gracefully degrade)
# ---------------------------------------------------------------------------
_HAS_SCAPY = False
_HAS_PYROUTE2 = False
_HAS_SPEEDTEST = False

try:
    from scapy.all import get_if_list, sniff  # noqa: F401
    _HAS_SCAPY = True
except ImportError:
    pass

try:
    from pyroute2 import IPRoute
    _HAS_PYROUTE2 = True
except ImportError:
    pass

try:
    import speedtest  # type: ignore[import-untyped]
    _HAS_SPEEDTEST = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# ── Constants ──────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------
REFRESH_FAST = 1.0  # seconds (CPU / RAM / network)
REFRESH_SLOW = 5.0  # seconds (services, containers, wifi, ports, ssh, vpn)
HISTORY_LEN = 60     # sparkline data-points

# ---------------------------------------------------------------------------
# ── Data helpers ───────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def _read_nvidia_gpu() -> list[dict[str, Any]]:
    """Query nvidia-smi for GPU utilisation."""
    try:
        out = subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            text=True,
            timeout=3,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return []
    gpus: list[dict[str, Any]] = []
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 6:
            gpus.append(
                {
                    "index": parts[0],
                    "name": parts[1],
                    "util": float(parts[2]),
                    "mem_used": int(parts[3]),
                    "mem_total": int(parts[4]),
                    "temp": int(parts[5]),
                }
            )
    return gpus


def _get_gpu_info() -> list[dict[str, Any]]:
    """Return GPU info; prefer nvidia-smi."""
    gpus = _read_nvidia_gpu()
    if gpus:
        return gpus
    # TODO: add AMD (rocm-smi) / Apple Metal stubs here if desired
    return []


def _detect_vpn() -> list[str]:
    """Detect active VPN interfaces via pyroute2 or /proc."""
    tunnels: list[str] = []
    if _HAS_PYROUTE2:
        try:
            with IPRoute() as ipr:
                for link in ipr.get_links():
                    attrs = {a[0]: a[1] for a in link.get("attrs", [])}
                    ifname = attrs.get("IFLA_IFNAME", "")
                    if any(k in ifname for k in ("tun", "tap", "wg", "tun0", "tap0", "ppp", "vpn", "utun")):
                        tunnels.append(ifname)
        except Exception:
            pass
    # fallback: scan /sys
    if not tunnels:
        try:
            for iface in os.listdir("/sys/class/net/"):
                if any(k in iface for k in ("tun", "tap", "wg", "ppp", "utun")):
                    tunnels.append(iface)
        except FileNotFoundError:
            pass
    return tunnels


def _active_ssh_sessions() -> list[str]:
    """Return list of established SSH session descriptors."""
    sessions: list[str] = []
    try:
        conns = psutil.net_connections()
    except Exception:
        conns = []
    for conn in conns:
        if conn.status == "ESTABLISHED" and conn.raddr and conn.laddr:
            if conn.laddr.port == 22 or conn.laddr.port == 2222 or conn.raddr.port == 22:
                sessions.append(f"{conn.laddr.ip}:{conn.laddr.port} ←→ {conn.raddr.ip}:{conn.raddr.port}")
    return sessions


def _docker_containers() -> list[dict[str, str]]:
    """Return a list of running Docker containers (name, status, image)."""
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}"],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return []
    containers: list[dict[str, str]] = []
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            containers.append(
                {"id": parts[0][:12], "image": parts[1], "name": parts[2], "status": parts[3]}
            )
    return containers


def _open_ports() -> list[str]:
    """Return listening (TCP) port strings."""
    seen: set[str] = set()
    ports: list[str] = []
    try:
        conns = psutil.net_connections(kind="tcp")
    except Exception:
        conns = []
    for conn in conns:
        if conn.status == "LISTEN" and conn.laddr:
            desc = f"{conn.laddr.port}"
            if desc not in seen:
                seen.add(desc)
                # Try to guess service name
                try:
                    svc = socket.getservbyport(conn.laddr.port, "tcp")
                    ports.append(f"{conn.laddr.port}/{svc}")
                except OSError:
                    ports.append(desc)
    return sorted(ports, key=lambda x: int(x.split("/")[0]))


def _running_services() -> list[dict[str, str]]:
    """Enumerate running systemd units (falls back to process list)."""
    services: list[dict[str, str]] = []
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend"],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                services.append({"name": parts[0], "status": parts[3]})
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        # fallback: show top CPU consumers
        procs = []
        for proc in psutil.process_iter(["name", "cpu_percent"]):
            try:
                name = proc.info.get("name") or "?"
                cpu = proc.info.get("cpu_percent")
                if cpu is None or isinstance(cpu, (Exception, str)):
                    cpu = 0.0
                procs.append({"name": name[:30], "cpu": cpu, "pid": proc.pid})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue
        procs.sort(key=lambda x: x["cpu"], reverse=True)
        for p in procs[:15]:
            services.append({"name": p["name"], "status": f"pid:{p['pid']} ({p['cpu']:.1f}%)"})
    return services


# ---------------------------------------------------------------------------
# ── Metric History Ring Buffer ─────────────────────────────────────────────
# ---------------------------------------------------------------------------

class MetricHistory:
    """Thread-safe-ish ring buffer for Rich Sparkline data."""

    def __init__(self, maxlen: int = HISTORY_LEN) -> None:
        self._data: deque[float] = deque(maxlen=maxlen)

    def push(self, val: float) -> None:
        self._data.append(val)

    def values(self) -> list[float]:
        return list(self._data)

    def last(self) -> float:
        return self._data[-1] if self._data else 0.0

    def __len__(self) -> int:
        return len(self._data)


# ---------------------------------------------------------------------------
# ── Custom Textual Widgets ─────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def make_sparkline(data: list[float], min_val: float | None = None, max_val: float | None = None) -> str:
    if not data:
        return ""
    if min_val is None:
        min_val = min(data)
    if max_val is None:
        max_val = max(data)
    
    val_range = max_val - min_val
    if val_range == 0:
        val_range = 1.0
        
    chars = " ▂▃▄▅▆▇█"
    num_chars = len(chars)
    
    spark = []
    for val in data:
        norm = (val - min_val) / val_range
        norm = min(max(norm, 0.0), 1.0)
        idx = int(norm * (num_chars - 1))
        spark.append(chars[idx])
    return "".join(spark)


class GaugeWithSparkline(Static):
    """A single horizontal gauge with a sparkline and label."""

    value = reactive(0.0)
    spark_data: list[float] = []

    def __init__(self, title: str, unit: str = "%", bar_width: int = 18, **kwargs):
        super().__init__(**kwargs)
        self._title = title
        self._unit = unit
        self._bar_width = bar_width

    def watch_value(self, val: float) -> None:
        self.refresh()

    def render(self) -> Panel:
        val = min(max(self.value, 0.0), 100.0)
        filled = int(round(val / 100 * self._bar_width))
        bar_chars = "█" * filled + "░" * (self._bar_width - filled)

        # colour thresholds
        color = "green"
        if val > 80:
            color = "red"
        elif val > 60:
            color = "yellow"

        label = Text(f"{self._title}: ", style="bold")
        label.append(f"{val:.1f}{self._unit}", style=color)

        sp_str = make_sparkline(self.spark_data[-30:]) if self.spark_data else ""
        sp = Text(sp_str, style="cyan")

        content = Text.assemble(
            label, "\n",
            Text(f"[{bar_chars}]", style=color), "\n",
            sp,
        )
        return Panel(content, border_style="dim", padding=(0, 1))


class NetStatWidget(Static):
    """Shows per-interface network traffic."""

    data = reactive({})

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._prev: dict[str, tuple[int, int]] = {}
        self._ts: float = time.monotonic()

    def refresh_io(self) -> None:
        now = time.monotonic()
        dt = now - self._ts
        counters = psutil.net_io_counters(pernic=True)
        rows: dict[str, str] = {}
        for iface, stats in sorted(counters.items()):
            rx_bytes = stats.bytes_recv
            tx_bytes = stats.bytes_sent
            rx_speed = tx_speed = 0.0
            if iface in self._prev and dt > 0:
                prx, ptx = self._prev[iface]
                rx_speed = (rx_bytes - prx) / dt
                tx_speed = (tx_bytes - ptx) / dt
            self._prev[iface] = (rx_bytes, tx_bytes)
            rows[iface] = f"↓ {_human_bytes(rx_speed)}/s  ↑ {_human_bytes(tx_speed)}/s"
        self._ts = now
        self.data = rows

    def render(self) -> Panel:
        tbl = Table.grid(padding=(0, 1))
        tbl.add_column()
        for iface, line in self.data.items():
            tbl.add_row(Text(f"🌐 {iface}", style="bold cyan"), line)
        return Panel(tbl, title="📡 Network", border_style="blue")


def _human_bytes(b: float) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if abs(b) < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}P"


class InfoTableWidget(Static):
    """Generic widget that renders a Rich Table from a list of dicts."""

    data = reactive([])

    def __init__(self, title: str, columns: list[str], field_map: list[str], **kwargs):
        super().__init__(**kwargs)
        self._title = title
        self._cols = columns
        self._fields = field_map

    def render(self) -> Panel:
        tbl = Table(title=self._title, expand=True, border_style="dim", title_justify="left")
        for col in self._cols:
            tbl.add_column(col)
        for row in self.data if self.data else []:
            tbl.add_row(*[str(row.get(f, "")) for f in self._fields])
        return Panel(tbl, border_style="green" if self.data else "dim")


# ---------------------------------------------------------------------------
# ── Main Dashboard App ──────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class HackerTerminal(App):
    """btop-for-hackers: real-time terminal dashboard."""

    TITLE = "⚡ HackerTerminal"
    CSS = """
Screen {
    background: #0d1117;
}

#grid {
    layout: grid;
    grid-size: 3 4;
    grid-gutter: 1;
    grid-columns: 1fr 1fr 1fr;
}

GaugeWithSparkline {
    height: auto;
    min-height: 6;
}

NetStatWidget {
    height: auto;
    min-height: 8;
    row-span: 2;
}

InfoTableWidget {
    height: auto;
    min-height: 6;
}

#footer {
    background: #161b22;
    color: #8b949e;
}
"""

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh All"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._cpu_hist = MetricHistory()
        self._ram_hist = MetricHistory()
        self._gpu_hist = MetricHistory()

    # ── compose ──────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="grid"):

            # Row 1 — CPU, RAM, GPU
            self.cpu_gauge = GaugeWithSparkline("CPU", "%")
            yield self.cpu_gauge

            self.ram_gauge = GaugeWithSparkline("RAM", "%")
            yield self.ram_gauge

            self.gpu_gauge = GaugeWithSparkline("GPU", "%")
            yield self.gpu_gauge

            # Row 2 — Network (spans 2 rows)
            self.net_widget = NetStatWidget()
            yield self.net_widget

            # Open Ports
            self.ports_widget = InfoTableWidget("🔓 Open Ports", ["Port"], ["port"])
            yield self.ports_widget

            # SSH Sessions
            self.ssh_widget = InfoTableWidget("🔑 SSH Sessions", ["Connection"], ["conn"])
            yield self.ssh_widget

            # Row 3 — Services / Docker / VPN
            self.services_widget = InfoTableWidget("⚙️ Services", ["Name", "Status"], ["name", "status"])
            yield self.services_widget

            self.docker_widget = InfoTableWidget("🐳 Docker", ["ID", "Image", "Name", "Status"], ["id", "image", "name", "status"])
            yield self.docker_widget

            # WiFi devices
            self.wifi_widget = InfoTableWidget("📶 WiFi Devices / Interfaces", ["Interface"], ["iface"])
            yield self.wifi_widget

            # VPN
            self.vpn_widget = InfoTableWidget("🔒 VPN Tunnels", ["Interface"], ["iface"])
            yield self.vpn_widget

        yield Footer()

    # ── on_mount ─────────────────────────────────────────────────────────

    async def on_mount(self) -> None:
        """Start background refresh tasks."""
        self.set_interval(REFRESH_FAST, self._update_fast)
        self.set_interval(REFRESH_SLOW, self._update_slow)
        # Initial fill
        await self._update_fast()
        await self._update_slow()

    # ── Fast (every 1 s) ────────────────────────────────────────────────

    async def _update_fast(self) -> None:
        # CPU
        cpu_pct = psutil.cpu_percent(interval=None)
        self._cpu_hist.push(cpu_pct)
        self.cpu_gauge.value = cpu_pct
        self.cpu_gauge.spark_data = self._cpu_hist.values()

        # RAM
        mem = psutil.virtual_memory()
        ram_pct = mem.percent
        self._ram_hist.push(ram_pct)
        self.ram_gauge.value = ram_pct
        self.ram_gauge.spark_data = self._ram_hist.values()

        # GPU
        gpus = _get_gpu_info()
        if gpus:
            gpu_pct = gpus[0]["util"]
        else:
            gpu_pct = 0.0
        self._gpu_hist.push(gpu_pct)
        self.gpu_gauge.value = gpu_pct
        self.gpu_gauge.spark_data = self._gpu_hist.values()

        # Network
        self.net_widget.refresh_io()

    # ── Slow (every 5 s) ────────────────────────────────────────────────

    async def _update_slow(self) -> None:
        # Open ports
        ports = _open_ports()
        self.ports_widget.data = [{"port": p} for p in ports]

        # SSH
        sshs = _active_ssh_sessions()
        self.ssh_widget.data = [{"conn": s} for s in sshs]

        # Services
        svcs = _running_services()
        self.services_widget.data = svcs

        # Docker
        containers = _docker_containers()
        self.docker_widget.data = containers

        # WiFi devices
        ifaces: list[str] = []
        if _HAS_SCAPY:
            try:
                ifaces = get_if_list()  # type: ignore[possibly-undefined]
            except Exception:
                pass
        if not ifaces:
            ifaces = list(psutil.net_if_stats().keys())
        self.wifi_widget.data = [{"iface": i} for i in ifaces[:12]]

        # VPN
        vpns = _detect_vpn()
        self.vpn_widget.data = [{"iface": v} for v in vpns] if vpns else [{"iface": "— none detected —"}]

    # ── Actions ─────────────────────────────────────────────────────────

    def action_refresh(self) -> None:
        self.call_from_thread(asyncio.create_task, self._update_fast())
        self.call_from_thread(asyncio.create_task, self._update_slow())


# ---------------------------------------------------------------------------
# ── Entry Point ────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def main() -> None:
    app = HackerTerminal()
    app.run()


if __name__ == "__main__":
    main()
