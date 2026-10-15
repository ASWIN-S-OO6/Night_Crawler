#!/usr/bin/env python3
"""E2E: full wizard + saved-provider lifecycle over a pty.

Phase 1 (first run): PROVIDER -> TARGET -> MODEL -> verify -> scan, and the
verified provider is saved to $HOME/.config/nightcrawler/provider.toml.
Phase 2 (second run): goes straight to TARGET with the saved agent — only
the target is asked for.

Runs against the mock NVIDIA server with an isolated HOME. Matching uses a
mini ANSI screen emulator (ratatui only rewrites changed cells)."""
import os, pty, fcntl, termios, struct, time, select, re, sys, glob, json, subprocess, shutil

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROVIDER_PATH = os.path.join(PROJECT, "tests/fixture/mock_provider.toml")
HOME = "/tmp/opencode/nc-e2e-home"
ROWS, COLS = 42, 130

def despaced(s):
    return re.sub(r"\s+", "", s)

class Screen:
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
                    self.r = max(0, int(m.group(1) or 1) - 1); self.c = max(0, int(m.group(2) or 1) - 1); i += m.end(); continue
                m = re.match(r"\x1b\[(\d*)K", text[i:])
                if m:
                    if (m.group(1) or "0") in ("0", "2"):
                        for x in range(self.c, self.cols): self.buf[self.r][x] = " "
                    i += m.end(); continue
                if re.match(r"\x1b\[2J", text[i:]):
                    self.buf = [[" "] * self.cols for _ in range(self.rows)]; i += 4; continue
                m = re.match(r"\x1b\[[0-9;?]*[A-Za-z]", text[i:])
                if m: i += m.end(); continue
                i += 1; continue
            if ch == "\r": self.c = 0; i += 1; continue
            if ch == "\n": self.r = min(self.r + 1, self.rows - 1); i += 1; continue
            if 0 <= self.r < self.rows and 0 <= self.c < self.cols:
                self.buf[self.r][self.c] = ch; self.c += 1
            i += 1
    def text(self):
        return "\n".join("".join(row).rstrip() for row in self.buf)

def start_rig():
    procs = []
    procs.append(subprocess.Popen(["python3", os.path.join(PROJECT, "tests/mock_nvidia.py")],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    os.makedirs("/tmp/opencode/nc-www", exist_ok=True)
    open("/tmp/opencode/nc-www/index.html", "w").write("<html><title>NC Test Page</title></html>")
    procs.append(subprocess.Popen(["python3", "-m", "http.server", "8000"], cwd="/tmp/opencode/nc-www",
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    procs.append(subprocess.Popen(
        ["bash", "-c", 'while true; do echo "220 ProFTPD 1.3.5 Server" | timeout 4 nc -l -p 9999 >/dev/null 2>&1 || true; done'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(1.2)
    return procs

def run_wizard(target, phase):
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(PROJECT)
        os.environ["HOME"] = HOME
        os.execvp("./target/debug/night-crawler", ["./target/debug/night-crawler"])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    raw = b""
    deadline = time.time() + 150
    stage = "start"
    observed = set()

    def send(s): os.write(fd, s.encode())
    def read(t=0.4):
        nonlocal raw
        r, _, _ = select.select([fd], [], [], t)
        if r:
            try:
                d = os.read(fd, 65536)
                if d: raw += d
            except OSError: pass
    def view():
        sc = Screen(ROWS, COLS)
        sc.feed(raw.decode("utf-8", "replace"))
        return despaced(sc.text())

    MARKERS = ["Step1—NVIDIAprovider", "Target(IPaddressordomain)", "savedagent:",
               "selectthemodelNightCrawlerwillrunas", "chatverifiedagainst"]
    while time.time() < deadline:
        read()
        d = view()
        for m in MARKERS:
            if m in d: observed.add(m)
        if stage == "start" and "Step1—NVIDIAprovider" in d:
            send(PROVIDER_PATH); time.sleep(0.4); send("\r"); stage = "connecting"
        elif stage == "start" and phase == 2 and "savedagent:" in d:
            # provider saved from run 1: straight to target
            send(target); time.sleep(0.4); send("\r"); stage = "verifying_wait"
        elif stage == "connecting" and "Target(IPaddressordomain)" in d:
            send(target); time.sleep(0.4); send("\r"); stage = "model_wait"
        elif stage == "model_wait" and "selectthemodelNightCrawlerwillrunas" in d:
            send("\r"); stage = "scanning"
        elif stage == "verifying_wait" and "NIGHTCRAWLER—COMPLETE" in d:
            time.sleep(1.5); read(1.0); break
        elif stage == "scanning" and "NIGHTCRAWLER—COMPLETE" in d:
            time.sleep(1.5); read(1.0); break
    try: os.kill(pid, 9)
    except ProcessLookupError: pass
    os.waitpid(pid, 0)
    return view(), observed

def main():
    shutil.rmtree(HOME, ignore_errors=True)
    os.makedirs(HOME, exist_ok=True)
    procs = start_rig()
    try:
        # ---- phase 1: full first-run wizard ----
        d1, obs1 = run_wizard("127.0.0.1", phase=1)
        saved = os.path.join(HOME, ".config/nightcrawler/provider.toml")
        saved_ok = os.path.exists(saved) and "nvapi-mock123" in open(saved).read()

        # ---- phase 2: saved provider -> only asks for the target ----
        d2, obs2 = run_wizard("127.0.0.1", phase=2)

        checks = {
            "run1: provider stage first": "Step1—NVIDIAprovider" in obs1,
            "run1: target stage": "Target(IPaddressordomain)" in obs1,
            "run1: connected + chat verified": "chatverifiedagainst" in obs1,
            "run1: model picker shown": "selectthemodelNightCrawlerwillrunas" in obs1,
            "run1: provider saved to provider.toml": saved_ok,
            "run1: scan completed": "NIGHTCRAWLER—COMPLETE" in d1,
            "run1: model in header/summary": "meta/llama-3.3-70b-instruct" in d1,
            "run2: goes straight to target (no provider stage)": "Step1—NVIDIAprovider" not in obs2 and "savedagent:" in obs2,
            "run2: scan completed with saved agent": "NIGHTCRAWLER—COMPLETE" in d2,
        }
        failed = 0
        for name, ok in checks.items():
            print(f"{'PASS' if ok else 'FAIL'}  {name}", flush=True)
            failed += 0 if ok else 1
        sys.exit(1 if failed else 0)
    finally:
        for p in procs: p.kill()

main()
