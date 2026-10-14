#!/usr/bin/env python3
"""Mock OpenAI-compatible server (NVIDIA NIM style) for Night Crawler integration tests.
Routes by prompt markers to exercise every NightCrawler decision point.
Usage: python3 tests/mock_nvidia.py [port]  (default 18700)"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT_STRATEGY = {"ports": "8000,9999,31337", "reason": "focused sweep of live test services"}
MODULE_PLAN = {"modules": ["snmp", "subdirs"], "priorities": ["verify ftp banner", "check web paths"],
               "rationale": "Web and legacy services detected; SNMP probe is harmless."}
FOLLOWUP = {"actions": [
    {"action": "extend_dirs", "bases": [], "words": ["index.html", "admin"]},
    {"action": "finish"}
], "reason": "confirm reachable content under the web root"}

REPORT_MD = """## Executive Summary

- 3 open services with one likely exploitable version (ProFTPD 1.3.5 mod_copy).

## Attack Paths

1. FTP foothold: connect to 9999, exploit ProFTPD 1.3.5 mod_copy (SITE CPFR/CPTO) to stage a webshell.
"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.endswith("/models"):
            body = json.dumps({"data": [{"id": "meta/llama-3.3-70b-instruct"},
                                        {"id": "qwen/qwen2.5-72b-instruct"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        auth = self.headers.get("Authorization", "")
        if auth != "Bearer nvapi-mock123":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error": {"message": "bad key"}}')
            return
        all_msgs = " ".join(m.get("content", "") for m in req.get("messages", []))
        if "Reply with exactly: OK" in all_msgs:
            content = "OK"
        elif 'Allowed values for "ports"' in all_msgs:
            content = json.dumps(PORT_STRATEGY)
        elif "Available optional modules" in all_msgs:
            content = json.dumps(MODULE_PLAN)
        elif "Allowed actions" in all_msgs:
            content = json.dumps(FOLLOWUP)
        else:
            content = REPORT_MD
        body = json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


port = int(sys.argv[1]) if len(sys.argv) > 1 else 18700
HTTPServer(("127.0.0.1", port), H).serve_forever()
