#!/usr/bin/env python3
"""Benign traffic generator.

Produces two populations against the victim:
  * fast clients  -- ordinary complete requests, served immediately;
  * slow clients  -- legitimate clients on a weak/high-latency link that send a
                     complete request, but slowly (a realistic honest-slow case).

The point is that the detector must NOT flag the slow-but-legitimate clients.
Each attempt is logged with its outcome so the legitimate-request success rate
can be computed before/during/after the attack and mitigation.
"""

import socket
import sys
import time

TARGET_HOST = "172.25.0.10"   # victim on SLNET
TARGET_PORT = 80

FAST_CLIENTS = 20             # complete, prompt requests
SLOW_CLIENTS = 5             # complete but slow (honest-slow)
SLOW_GAP_SECONDS = 2        # delay between header lines for honest-slow clients
ROUNDS = 30                  # repeat so we cover before/during/after phases
AVAIL_THRESHOLD = 60.0       # % success below which availability is "degraded"

LOG_PATH = "/var/log/benign.log"


def log(msg):
    line = "%s BENIGN %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except PermissionError:
        pass


def fast_request():
    """A normal client: send a complete request at once, read the status line."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        req = ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
               % TARGET_HOST)
        s.sendall(req.encode())
        resp = s.recv(64)
        ok = resp.startswith(b"HTTP/1.1 2") or resp.startswith(b"HTTP/1.0 2")
        log("fast %s" % ("SUCCESS" if ok else "FAIL"))
        return ok
    except socket.error:
        log("fast FAIL")
        return False
    finally:
        s.close()


def slow_request():
    """An honest-slow client: a COMPLETE request, but sent line by line slowly."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SLOW_GAP_SECONDS * 6 + 10)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        for line in (b"GET / HTTP/1.1\r\n",
                     b"Host: %s\r\n" % TARGET_HOST.encode(),
                     b"Connection: close\r\n",
                     b"\r\n"):                      # crucial: it DOES complete
            s.send(line)
            time.sleep(SLOW_GAP_SECONDS)
        resp = s.recv(64)
        ok = resp.startswith(b"HTTP/1.1 2") or resp.startswith(b"HTTP/1.0 2")
        log("slow %s" % ("SUCCESS" if ok else "FAIL"))
        return ok
    except socket.error:
        log("slow FAIL")
        return False
    finally:
        s.close()


def main():
    # Phase label lets grading tell the three runs apart:
    #   baseline (no attack), during (attack on), after (mitigation on).
    phase = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    log("start phase=%s target=%s:%d fast=%d slow=%d rounds=%d"
        % (phase, TARGET_HOST, TARGET_PORT, FAST_CLIENTS, SLOW_CLIENTS, ROUNDS))
    total = ok = 0
    for r in range(ROUNDS):
        for _ in range(FAST_CLIENTS):
            total += 1
            ok += 1 if fast_request() else 0
        for _ in range(SLOW_CLIENTS):
            total += 1
            ok += 1 if slow_request() else 0
        rate = (100.0 * ok / total) if total else 0.0
        log("round=%d cumulative_success_rate=%.1f%% (%d/%d)"
            % (r, rate, ok, total))
        time.sleep(1)
    rate = (100.0 * ok / total) if total else 0.0
    verdict = "DEGRADED" if rate < AVAIL_THRESHOLD else "OK"
    log("done phase=%s success_rate=%.1f%% (%d/%d)" % (phase, rate, ok, total))
    # Contiguous marker for automated grading (CONTAINS-friendly).
    log("RESULT phase=%s verdict=%s" % (phase, verdict))


if __name__ == "__main__":
    main()
