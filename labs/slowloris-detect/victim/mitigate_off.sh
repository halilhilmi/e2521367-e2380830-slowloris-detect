#!/bin/bash
# Revert to the vulnerable baseline: disable mod_reqtimeout and clear the
# per-source connection cap. Useful for comparing before/after.

sudo a2dismod reqtimeout >/dev/null 2>&1
sudo systemctl restart apache2
sudo iptables -D INPUT -p tcp --syn --dport 80 \
    -m connlimit --connlimit-above 20 --connlimit-mask 32 -j REJECT \
    --reject-with tcp-reset 2>/dev/null
echo "mitigation disabled (back to vulnerable baseline)"
