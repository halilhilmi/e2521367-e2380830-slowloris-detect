#!/usr/bin/env python3
"""Connection-state Slowloris detector (custom implementation).

Watches HTTP traffic on the LAN and keeps, per source IP, how many connections
are open at once and how long each has sat in the header-reading phase without
completing (no blank line / CRLFCRLF yet). A source is flagged as Slowloris when
it holds many connections open AND those connections stay in the slow header
phase -- the combination is what separates the attack from honest-slow clients,
which only ever hold a few connections and do finish their requests.

CONC_THRESHOLD and SLOW_THRESHOLD are individualized by parameter.config.

NOTE ON VISIBILITY: this uses a shared-segment packet capture (scapy). It only
works if the monitor can actually observe the attacker<->victim packets. On an
isolated LAN with a hub/mirror that holds; on a plain switched bridge you may
instead need to run this logic as an on-host agent on the victim (reading `ss`/
/proc/net/tcp). Both placements are discussed in the proposal; this file
implements the capture-based monitor.
"""

import threading
import time

from scapy.all import sniff, TCP, IP, Raw

VICTIM_IP = "172.25.0.10"
VICTIM_PORT = 80

# ---- Individualized by parameter.config (RAND_REPLACE) ----
CONC_THRESHOLD = CONC_THRESHOLD    # concurrent incomplete conns per source
SLOW_THRESHOLD = SLOW_THRESHOLD    # seconds a conn may sit in header phase
# ----------------------------------------------------------

CHECK_EVERY = 2          # seconds between evaluations
LOG_PATH = "/var/log/detector.log"

# conns[(src_ip, src_port)] = {"start": t, "last": t, "complete": bool}
conns = {}
flagged = set()
lock = threading.Lock()


def log(msg):
    line = "%s DETECTOR %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except PermissionError:
        pass


def on_packet(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    ip, tcp = pkt[IP], pkt[TCP]
    # Only care about client -> victim:80 traffic.
    if ip.dst != VICTIM_IP or tcp.dport != VICTIM_PORT:
        return
    key = (ip.src, tcp.sport)
    now = time.time()
    with lock:
        flags = tcp.flags
        if flags & 0x02:                       # SYN: new connection
            conns[key] = {"start": now, "last": now, "complete": False}
            return
        if flags & 0x01 or flags & 0x04:       # FIN or RST: connection closed
            conns.pop(key, None)
            return
        entry = conns.setdefault(key, {"start": now, "last": now,
                                       "complete": False})
        entry["last"] = now
        # A request that includes the terminating blank line is "complete"
        # (an honest client), so it no longer counts as a held-open header conn.
        if pkt.haslayer(Raw) and b"\r\n\r\n" in bytes(pkt[Raw].load):
            entry["complete"] = True


def evaluate():
    while True:
        time.sleep(CHECK_EVERY)
        now = time.time()
        per_src = {}
        with lock:
            for (src_ip, _sport), e in conns.items():
                if e["complete"]:
                    continue
                age = now - e["start"]
                if age < SLOW_THRESHOLD:
                    continue
                per_src.setdefault(src_ip, 0)
                per_src[src_ip] += 1
        for src_ip, slow_open in per_src.items():
            if slow_open >= CONC_THRESHOLD and src_ip not in flagged:
                flagged.add(src_ip)
                log("DETECTED SLOWLORIS src=%s slow_open_conns=%d "
                    "conc_threshold=%d slow_threshold=%ds"
                    % (src_ip, slow_open, CONC_THRESHOLD, SLOW_THRESHOLD))
                log("MITIGATE src=%s action=cap_per_ip_connections+"
                    "request_receive_timeout" % src_ip)


def main():
    log("start watching %s:%d conc_threshold=%d slow_threshold=%ds"
        % (VICTIM_IP, VICTIM_PORT, CONC_THRESHOLD, SLOW_THRESHOLD))
    t = threading.Thread(target=evaluate, daemon=True)
    t.start()
    sniff(filter="tcp port %d" % VICTIM_PORT, prn=on_packet, store=False)


if __name__ == "__main__":
    main()
