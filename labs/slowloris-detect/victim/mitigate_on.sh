#!/bin/bash
# Enable the Slowloris mitigation on the victim:
#   * mod_reqtimeout  -- drops connections that send headers too slowly;
#   * a per-source connection cap (iptables connlimit) so one host cannot hold
#     enough connections open to exhaust the worker pool.
# Run this AFTER observing that the baseline attack degrades availability, to
# show that availability recovers.

sudo tee /etc/apache2/mods-available/reqtimeout.conf >/dev/null <<'EOF'
<IfModule reqtimeout_module>
    RequestReadTimeout header=5-10,MinRate=500 body=10,MinRate=500
</IfModule>
EOF
sudo a2enmod reqtimeout >/dev/null 2>&1
sudo systemctl restart apache2

# Cap concurrent connections to :80 from any single source IP.
sudo iptables -A INPUT -p tcp --syn --dport 80 \
    -m connlimit --connlimit-above 20 --connlimit-mask 32 -j REJECT \
    --reject-with tcp-reset 2>/dev/null

echo "mitigation enabled (mod_reqtimeout + per-IP connection cap)"
