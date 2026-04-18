"""
Clean terminal UI with progress bars
Professional, minimal scanning interface
"""

import sys
import time
import threading
import re
from typing import List, Optional
from datetime import datetime


class Colors:
    # Severity colors
    CRITICAL = "\033[38;5;196m"  # Bright red
    HIGH = "\033[38;5;202m"      # Orange
    MEDIUM = "\033[38;5;220m"    # Yellow
    LOW = "\033[38;5;33m"        # Blue
    INFO = "\033[38;5;245m"      # Gray

    # UI colors
    CYAN = "\033[38;5;51m"
    GREEN = "\033[38;5;46m"
    PURPLE = "\033[38;5;141m"
    WHITE = "\033[38;5;255m"
    DIM = "\033[38;5;240m"
    RED = "\033[38;5;196m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[38;5;226m"

    # Styles
    BOLD = "\033[1m"
    DIM_STYLE = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

    # Cursor control
    HIDE_CURSOR = "\033[?25l"
    SHOW_CURSOR = "\033[?25h"
    CLEAR_LINE = "\033[2K"


SEVERITY_COLORS = {
    "CRITICAL": Colors.CRITICAL,
    "HIGH": Colors.HIGH,
    "MEDIUM": Colors.MEDIUM,
    "LOW": Colors.LOW,
    "INFO": Colors.INFO,
}

SEVERITY_ICONS = {
    "CRITICAL": "◉",
    "HIGH": "◈",
    "MEDIUM": "◇",
    "LOW": "○",
    "INFO": "·",
}


BANNER = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║{Colors.RESET}                                                                              {Colors.CYAN}║
║  {Colors.GREEN}██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗{Colors.CYAN}       ║
║  {Colors.GREEN}██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║{Colors.CYAN}       ║
║  {Colors.GREEN}██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║{Colors.CYAN}       ║
║  {Colors.GREEN}╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║{Colors.CYAN}       ║
║  {Colors.GREEN} ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║{Colors.CYAN}       ║
║  {Colors.GREEN}  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Colors.CYAN}       ║
║{Colors.RESET}                                                                              {Colors.CYAN}║
║  {Colors.PURPLE}Adaptive Vulnerability Scanner{Colors.DIM} · v2.0 · AI-Powered{Colors.CYAN}                        ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes for length calculation"""
    return re.sub(r'\033\[[0-9;]*m', '', text)


# ─── Progress Bar ────────────────────────────────────────────────────────────

class ProgressBar:
    """Clean, in-place updating progress bar with percentage"""

    def __init__(self, total: int, label: str, bar_width: int = 40, color: str = Colors.CYAN):
        self.total = max(total, 1)
        self.completed = 0
        self.label = label
        self.bar_width = bar_width
        self.color = color
        self.current_task = ""
        self._lock = threading.Lock()
        self._active = True

    def _render(self) -> str:
        """Render the progress bar as a single line"""
        pct = min(self.completed / self.total, 1.0)
        filled = int(self.bar_width * pct)
        empty = self.bar_width - filled

        bar = f"{self.color}{'━' * filled}{Colors.DIM}{'━' * empty}{Colors.RESET}"
        pct_str = f"{int(pct * 100):>3d}%"
        task = self.current_task[:28] if self.current_task else ""

        return (
            f"\r  {self.color}{self.label:<11}{Colors.RESET}"
            f" {bar}"
            f"  {Colors.BOLD}{Colors.WHITE}{pct_str}{Colors.RESET}"
            f"  {Colors.DIM}{task}{Colors.RESET}\033[K"
        )

    def update(self, task: str = ""):
        """Update current task label without advancing progress"""
        with self._lock:
            if task:
                self.current_task = task
            if self._active:
                sys.stdout.write(self._render())
                sys.stdout.flush()

    def advance(self, task: str = ""):
        """Advance progress by 1 step and update display"""
        with self._lock:
            self.completed = min(self.completed + 1, self.total)
            if task:
                self.current_task = task
            if self._active:
                sys.stdout.write(self._render())
                sys.stdout.flush()

    def print_above(self, text: str):
        """Print a line above the progress bar, then reprint the bar"""
        with self._lock:
            sys.stdout.write(f"\r\033[K{text}\n")
            if self._active:
                sys.stdout.write(self._render())
            sys.stdout.flush()

    def finish(self, status: str = "Complete"):
        """Mark as 100% complete with final status"""
        with self._lock:
            self.completed = self.total
            self.current_task = f"{Colors.GREEN}✓{Colors.RESET} {Colors.DIM}{status}{Colors.RESET}"
            sys.stdout.write(self._render() + "\n")
            self._active = False
            sys.stdout.flush()


# ─── Lightweight Terminal Manager ────────────────────────────────────────────

class LiveTerminal:
    """Minimal terminal state manager"""

    def __init__(self):
        self._lock = threading.Lock()
        self._findings_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        self._start_time = time.time()

    def start(self):
        sys.stdout.write(Colors.HIDE_CURSOR)
        sys.stdout.flush()
        self._start_time = time.time()

    def stop(self):
        sys.stdout.write(Colors.SHOW_CURSOR)
        sys.stdout.flush()

    def log_activity(self, action: str, detail: str = "", level: str = "info"):
        """No-op — replaced by progress bars"""
        pass

    def set_module(self, module_name: str):
        pass

    def set_action(self, action: str):
        pass

    def add_finding(self, severity: str):
        with self._lock:
            if severity in self._findings_count:
                self._findings_count[severity] += 1

    def get_findings_summary(self) -> str:
        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self._findings_count[sev]
            if count > 0:
                color = SEVERITY_COLORS[sev]
                icon = SEVERITY_ICONS[sev]
                parts.append(f"{color}{icon}{count}{Colors.RESET}")
        return " ".join(parts) if parts else f"{Colors.DIM}0{Colors.RESET}"


# ─── Per-Module Progress ─────────────────────────────────────────────────────

class ModuleProgress:
    """Track individual module progress via the scan progress bar"""

    def __init__(self, name: str, terminal: LiveTerminal,
                 scan_bar: 'ProgressBar' = None, ui: 'ScanUI' = None):
        self.name = name
        self.terminal = terminal
        self.scan_bar = scan_bar
        self.ui = ui
        self.status = "pending"
        self.findings_count = 0
        self.start_time = None
        self.end_time = None

    def start(self):
        self.status = "running"
        self.start_time = time.time()
        if self.scan_bar:
            self.scan_bar.update(self.name)

    def update(self, check_name: str, detail: str = ""):
        """Silent — just keeps the bar label on the current module"""
        if self.scan_bar:
            self.scan_bar.update(self.name)

    def found(self, vuln_type: str, severity: str, detail: str = ""):
        """Print a finding notification above the progress bar"""
        self.findings_count += 1
        self.terminal.add_finding(severity)
        if self.ui:
            self.ui.log_finding(severity, vuln_type, detail)

    def finish(self, findings: int = None):
        self.status = "done"
        if findings is not None:
            self.findings_count = findings
        self.end_time = time.time()
        if self.scan_bar:
            self.scan_bar.advance()

    def error(self, message: str = ""):
        self.status = "error"
        self.end_time = time.time()
        if self.scan_bar:
            self.scan_bar.advance()

    @property
    def elapsed(self) -> float:
        if self.start_time:
            end = self.end_time or time.time()
            return end - self.start_time
        return 0


# ─── Main Scan UI ────────────────────────────────────────────────────────────

class ScanUI:
    """Main scan UI controller — progress bars + clean output"""

    W = 76  # standard content width

    def __init__(self):
        self.terminal = LiveTerminal()
        self.modules: List[ModuleProgress] = []
        self.findings: List[dict] = []
        self._target = ""
        self._profile = None
        self._scan_bar: Optional[ProgressBar] = None
        self._verify_bar: Optional[ProgressBar] = None
        self._findings_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        self._banner_printed = False

    def start(self, target: str, profile=None):
        self._target = target
        self._profile = profile
        self.terminal.start()

    def stop(self):
        self.terminal.stop()

    # ── Progress bars ──────────────────────────────────────────────────

    def create_scan_bar(self, total_modules: int) -> ProgressBar:
        """Create the main scanning progress bar"""
        self._scan_bar = ProgressBar(total_modules, "Scanning", color=Colors.CYAN)
        self._scan_bar.update("Initializing...")
        return self._scan_bar

    def create_verify_bar(self, total_steps: int) -> ProgressBar:
        """Create the AI verification progress bar"""
        self._verify_bar = ProgressBar(total_steps, "Verifying", color=Colors.PURPLE)
        self._verify_bar.update("Initializing...")
        return self._verify_bar

    # ── Modules ────────────────────────────────────────────────────────

    def add_module(self, name: str) -> ModuleProgress:
        module = ModuleProgress(name, self.terminal, self._scan_bar, self)
        self.modules.append(module)
        return module

    def add_finding(self, finding: dict):
        self.findings.append(finding)

    def log_finding(self, severity: str, vuln_class: str, url: str = ""):
        """Print a one-line finding notification above the active progress bar"""
        self._findings_count[severity] = self._findings_count.get(severity, 0) + 1
        color = SEVERITY_COLORS.get(severity, Colors.DIM)
        icon = SEVERITY_ICONS.get(severity, "·")

        url_short = url[:45] + "..." if len(url) > 48 else url
        line = (
            f"  {color}{icon}{Colors.RESET} "
            f"{color}{vuln_class}{Colors.RESET} "
            f"{Colors.DIM}[{severity}]{Colors.RESET}"
        )
        if url_short:
            line += f" {Colors.DIM}{url_short}{Colors.RESET}"

        bar = self._scan_bar or self._verify_bar
        if bar and bar._active:
            bar.print_above(line)
        else:
            print(line)

    # ── Headers & output ───────────────────────────────────────────────

    def print_header(self):
        """Print banner (once) + target info"""
        if not self._banner_printed:
            print(BANNER)
            self._banner_printed = True

        w = self.W
        print(f"  {Colors.DIM}{'─' * w}{Colors.RESET}")
        print(f"  {Colors.BOLD}{Colors.WHITE}TARGET{Colors.RESET}   {Colors.WHITE}{self._target}{Colors.RESET}")

        if self._profile:
            if self._profile.technologies:
                techs = ", ".join(
                    f"{t.name}" + (f"/{t.version}" if t.version else "")
                    for t in self._profile.technologies[:5]
                )
                if len(techs) > 60:
                    techs = techs[:57] + "..."
                print(f"  {Colors.BOLD}{Colors.WHITE}STACK{Colors.RESET}    {Colors.PURPLE}{techs}{Colors.RESET}")

            if self._profile.waf_detected:
                print(f"  {Colors.BOLD}{Colors.WHITE}WAF{Colors.RESET}      {Colors.ORANGE}{self._profile.waf_detected}{Colors.RESET}")

        print(f"  {Colors.BOLD}{Colors.WHITE}TIME{Colors.RESET}     {Colors.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"  {Colors.DIM}{'─' * w}{Colors.RESET}")
        print()

    def print_activity_footer(self):
        """No-op — replaced by progress bar finish()"""
        pass

    # ── Results rendering ──────────────────────────────────────────────

    def render_findings_summary(self):
        """Render clean one-line findings summary"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        w = self.W
        print(f"\n  {Colors.DIM}{'─' * w}{Colors.RESET}")

        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts[sev] > 0:
                color = SEVERITY_COLORS[sev]
                icon = SEVERITY_ICONS[sev]
                parts.append(f"{color}{icon} {counts[sev]} {sev}{Colors.RESET}")

        if parts:
            print(f"  {Colors.BOLD}{Colors.WHITE}RESULTS{Colors.RESET}  {Colors.DIM}│{Colors.RESET}  {'   '.join(parts)}")
        else:
            print(f"  {Colors.GREEN}✓ No vulnerabilities found{Colors.RESET}")

        print(f"  {Colors.DIM}{'─' * w}{Colors.RESET}")

    def render_finding(self, finding: dict, index: int):
        """Render a single finding in detail"""
        sev = finding.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, Colors.DIM)
        icon = SEVERITY_ICONS.get(sev, "·")
        cvss = finding.get("cvss", "N/A")
        vuln_class = finding.get("vuln_class", "Unknown")
        url = finding.get("url", "")

        if len(vuln_class) > 40:
            vuln_class = vuln_class[:37] + "..."

        w = self.W

        print(f"\n  {color}{'─' * w}{Colors.RESET}")
        print(
            f"  {color}{icon}{Colors.RESET} "
            f"{Colors.BOLD}#{index}{Colors.RESET}  "
            f"{color}{Colors.BOLD}{sev}{Colors.RESET} "
            f"{Colors.DIM}CVSS {cvss}{Colors.RESET}  "
            f"{Colors.DIM}│{Colors.RESET}  "
            f"{Colors.WHITE}{vuln_class}{Colors.RESET}"
        )
        print(f"  {color}{'─' * w}{Colors.RESET}")

        # URL
        url_display = url[:70] if len(url) <= 70 else url[:67] + "..."
        print(f"  {Colors.BOLD}URL{Colors.RESET}      {url_display}")

        # Description
        desc = finding.get("description", "")
        if desc:
            words = desc.split()
            lines = []
            current_line = ""
            for word in words:
                if len(current_line) + len(word) + 1 <= 70:
                    current_line += (" " if current_line else "") + word
                else:
                    lines.append(current_line)
                    current_line = word
            if current_line:
                lines.append(current_line)

            for line in lines[:3]:
                print(f"  {Colors.DIM}{line}{Colors.RESET}")

        # Evidence
        evidence = finding.get("evidence", finding.get("raw_evidence", ""))
        if evidence and not isinstance(evidence, dict):
            ev_str = str(evidence)[:65]
            print(f"  {Colors.DIM}Evidence: {ev_str}{Colors.RESET}")

        # PoC for critical / high
        poc = finding.get('poc_curl', '')
        if poc and finding.get('severity') in ['CRITICAL', 'HIGH']:
            print(f"  {Colors.DIM}PoC:{Colors.RESET}")
            for poc_line in poc.split('\n')[:3]:
                print(f"    {Colors.GREEN}{poc_line[:72]}{Colors.RESET}")

    # ── Phase display (extensive mode) ────────────────────────────────

    PHASE_COLORS = {
        1: Colors.CYAN,
        2: Colors.PURPLE,
        3: Colors.ORANGE,
        4: Colors.RED,
        5: Colors.GREEN,
    }

    def print_phase_header(self, phase_num: int, phase_name: str):
        """Print a phase separator header with color"""
        w = self.W
        color = self.PHASE_COLORS.get(phase_num, Colors.CYAN)
        print(f"\n  {color}{'━' * w}{Colors.RESET}")
        print(
            f"  {color}{Colors.BOLD}PHASE {phase_num}{Colors.RESET}  "
            f"{Colors.DIM}│{Colors.RESET}  "
            f"{Colors.BOLD}{Colors.WHITE}{phase_name}{Colors.RESET}"
        )
        print(f"  {color}{'━' * w}{Colors.RESET}")

    def print_phase_footer(self):
        """Close the current phase block"""
        w = self.W
        print(f"  {Colors.DIM}{'─' * w}{Colors.RESET}")

    def print_phase_stat(self, label: str, value):
        """Print a single stat line inside a phase"""
        print(
            f"  {Colors.BOLD}{Colors.WHITE}{label}{Colors.RESET}  "
            f"{Colors.DIM}{value}{Colors.RESET}"
        )

    def create_phase_bar(self, total: int, label: str, color: str = Colors.CYAN) -> ProgressBar:
        """Create a progress bar for a specific phase"""
        bar = ProgressBar(total, label, color=color)
        bar.update("Initializing...")
        return bar

    # ── Findings rendering ─────────────────────────────────────────────

    def render_all_findings(self):
        """Render all findings sorted by severity"""
        sorted_findings = sorted(
            self.findings,
            key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(
                f.get("severity", "INFO")
            ),
        )
        for i, f in enumerate(sorted_findings, 1):
            self.render_finding(f, i)


# ─── Standalone helpers ──────────────────────────────────────────────────────

def print_banner():
    print(BANNER)


def print_scan_complete(elapsed: float, findings_count: int,
                        critical: int = 0, high: int = 0):
    """Print clean scan-complete footer"""
    if critical > 0:
        status_color = Colors.RED
        status_icon = "◉"
        status_text = f"{critical} CRITICAL"
    elif high > 0:
        status_color = Colors.ORANGE
        status_icon = "◈"
        status_text = f"{high} HIGH"
    elif findings_count > 0:
        status_color = Colors.YELLOW
        status_icon = "◇"
        status_text = f"{findings_count} findings"
    else:
        status_color = Colors.GREEN
        status_icon = "✓"
        status_text = "SECURE"

    w = 76
    print(f"\n  {Colors.GREEN}{'═' * w}{Colors.RESET}")
    print(
        f"  {Colors.GREEN}{Colors.BOLD}SCAN COMPLETE{Colors.RESET}  "
        f"{Colors.DIM}│{Colors.RESET}  "
        f"{Colors.WHITE}{elapsed:.1f}s{Colors.RESET}  "
        f"{Colors.DIM}│{Colors.RESET}  "
        f"{status_color}{status_icon} {status_text}{Colors.RESET}"
    )
    print(f"  {Colors.GREEN}{'═' * w}{Colors.RESET}\n")
