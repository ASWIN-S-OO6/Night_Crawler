#!/usr/bin/env python3
"""E2E: drive the Night Crawler setup wizard over a pty like a real user.
Wizard order: PROVIDER first (connect + chat verify) -> TARGET -> MODEL -> scan.
Starts the mock NVIDIA server and local test services itself.

Matching runs against a reconstructed screen buffer (mini ANSI emulator),
because ratatui's cell-diff renderer only rewrites changed cells in the
raw pty byte stream."""
import os, pty, fcntl, termios, struct, time, select, re, sys, glob, json, subprocess

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROVIDER_PATH = os.path.join(PROJECT, "tests/fixture/mock_provider.toml")
ROWS, COLS = 42, 130

def despaced(s):
    return re.sub(r"\s+", "", s)

def start_rig():
    procs = []
    procs.append(subprocess.Popen(
        ["python3", os.path.join(PROJECT, "tests/mock_nvidia.py")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    os.makedirs("/tmp/opencode/nc-www", exist_ok=True)
    with open("/tmp/opencode/nc-www/index.html", "w") as f:
        f.write("<html><title>NC Test Page</title></html>")
    procs.append(subprocess.Popen(
        ["python3", "-m", "http.server", "8000"], cwd="/tmp/opencode/nc-www",
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    procs.append(subprocess.Popen(
        ["bash", "-c", 'while true; do echo "220 ProFTPD 1.3.5 Server" | timeout 4 nc -l -p 9999 >/dev/null 2>&1 || true; done'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(1.2)
    return procs

class Screen:
    """Tiny VT emulator: enough for ratatui output (CUP, EL, ED, printable)."""
    def __init__(self, rows, cols):
        self.rows, self.cols = rows, cols
        self.buf = [[" "] * cols for _ in range(rows)]
        self.r = self.c = 0

    def feed(self, text):
        i, n = 0, len(text)
        while i < n:
            ch = text[i]
            if ch == "\x1b":
                m = re.match(r"\x1b\[(\d*);(\d*)H", text[i:])
                if m:
                    self.r = max(0, int(m.group(1) or 1) - 1)
                    self.c = max(0, int(m.group(2) or 1) - 1)
                    i += m.end(); continue
                m = re.match(r"\x1b\[(\d*)K", text[i:])
                if m:
                    mode = m.group(1) or "0"
                    if mode in ("0", "2"):
                        for x in range(self.c, self.cols):
                            self.buf[self.r][x] = " "
                    elif mode == "1":
                        for x in range(0, self.c + 1):
                            self.buf[self.r][x] = " "
                    i += m.end(); continue
                if re.match(r"\x1b\[2J", text[i:]):
                    self.buf = [[" "] * self.cols for _ in range(self.rows)]
                    i += 4; continue
                m = re.match(r"\x1b\[[0-9;?]*[A-Za-z]", text[i:])
                if m: i += m.end(); continue
                m = re.match(r"\x1b[()][A-Z0-9]", text[i:])
                if m: i += m.end(); continue
                i += 1; continue
            if ch == "\r": self.c = 0; i += 1; continue
            if ch == "\n":
                self.r = min(self.r + 1, self.rows - 1); i += 1; continue
            if ch == "\x08":
                self.c = max(0, self.c - 1); i += 1; continue
            if 0 <= self.r < self.rows and 0 <= self.c < self.cols:
                self.buf[self.r][self.c] = ch
                self.c += 1
            i += 1

    def text(self):
        return "\n".join("".join(row).rstrip() for row in self.buf)

def main():
    procs = start_rig()
    try:
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(PROJECT)
            os.execvp("./target/debug/night-crawler", ["./target/debug/night-crawler"])
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

        raw = b""
        deadline = time.time() + 150
        stage = "provider"

        def send(s):
            os.write(fd, s.encode())

        def read(t=0.4):
            nonlocal raw
            r, _, _ = select.select([fd], [], [], t)
            if r:
                try:
                    d = os.read(fd, 65536)
                    if d:
                        raw += d
                except OSError:
                    pass

        def view():
            sc = Screen(ROWS, COLS)
            sc.feed(raw.decode("utf-8", "replace"))
            return despaced(sc.text())

        observed = set()
        WIZARD_MARKERS = [
            "Step1—NVIDIAprovider",
            "Target(IPaddressordomain)",
            "selectthemodelNightCrawlerwillrunas",
            "Provideronline",
        ]

        while time.time() < deadline:
            read()
            d = view()
            for m in WIZARD_MARKERS:
                if m in d:
                    observed.add(m)

            if stage == "provider" and "Step1—NVIDIAprovider" in d:
                send(PROVIDER_PATH)
                time.sleep(0.4)
                send("\r")
                stage = "connecting"
                continue
            if stage == "connecting" and "Target(IPaddressordomain)" in d:
                send("127.0.0.1")
                time.sleep(0.4)
                send("\r")
                stage = "model_wait"
                continue
            if stage == "model_wait" and "selectthemodelNightCrawlerwillrunas" in d:
                send("\r")  # accept preselected model, start scan
                stage = "scanning"
                continue
            if stage == "scanning" and "NIGHTCRAWLER—COMPLETE" in d:
                time.sleep(1.5)
                read(1.0)
                break

        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)

        d = view()

        # verify NightCrawler decisions + vuln confidence from the written findings.json
        report_dirs = sorted(
            glob.glob(os.path.join(PROJECT, "reports/nightcrawler_*")),
            key=os.path.getmtime,
        )
        followup_ok = False
        vuln_ok = False
        if report_dirs:
            fj = os.path.join(report_dirs[-1], "findings.json")
            if os.path.exists(fj):
                data = json.load(open(fj))
                decisions = [x["decision"] for x in data.get("ai_decisions", [])]
                followup_ok = any("extend_dirs" in dec for dec in decisions)
                vuln_ok = any(v.get("confidence") == "LIKELY" and "ProFTPD" in v.get("title", "")
                              for v in data.get("vulns", []))

        checks = {
            "wizard: provider stage first": "Step1—NVIDIAprovider" in observed,
            "wizard: target stage second": "Target(IPaddressordomain)" in observed,
            "wizard: connected + chat verified": "Provideronline" in observed,
            "wizard: model select stage": "selectthemodelNightCrawlerwillrunas" in observed,
            "wizard: model shown": "meta/llama-3.3-70b-instruct" in d,
            "scan: NightCrawler port strategy": "Portstrategy:8000,9999,31337" in d,
            "scan: NightCrawler module plan": "Moduleplan:" in d,
            "scan: NightCrawler follow-up executed": followup_ok,
            "scan: vuln confidence (LIKELY) recorded": vuln_ok,
            "scan: model in header/summary": "meta/llama-3.3-70b-instruct" in d,
            "scan: report written": "report:" in d,
            "scan: complete banner": "NIGHTCRAWLER—COMPLETE" in d,
        }
        failed = 0
        for name, ok in checks.items():
            print(f"{'PASS' if ok else 'FAIL'}  {name}", flush=True)
            failed += 0 if ok else 1
        sys.exit(1 if failed else 0)
    finally:
        for p in procs:
            p.kill()

main()
