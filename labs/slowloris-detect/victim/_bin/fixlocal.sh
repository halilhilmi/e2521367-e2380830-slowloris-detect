#!/bin/bash
# Configure Apache to use the prefork MPM with a deliberately small worker pool,
# which is what makes the server vulnerable to Slowloris. The real mitigation
# (mod_reqtimeout) is left DISABLED by default so the attack works; the lab
# enables it later with mitigate_on.sh to demonstrate the defense.

sudo a2dismod -f mpm_event  >/dev/null 2>&1
sudo a2dismod -f mpm_worker >/dev/null 2>&1
sudo a2enmod mpm_prefork    >/dev/null 2>&1

sudo tee /etc/apache2/mods-available/mpm_prefork.conf >/dev/null <<'EOF'
<IfModule mpm_prefork_module>
    StartServers             5
    MinSpareServers          5
    MaxSpareServers          10
    MaxRequestWorkers        20
    MaxConnectionsPerChild   0
</IfModule>
EOF

# mod_reqtimeout = the defense. Disabled by default (vulnerable baseline).
sudo a2dismod reqtimeout >/dev/null 2>&1

sudo systemctl enable apache2 >/dev/null 2>&1
sudo systemctl restart apache2
