#!/bin/bash
# setup_nginx_modsec.sh - Locally installs Nginx, compiles/configures ModSecurity v3 with OWASP CRS.
# Target OS: Linux (Ubuntu/Debian)

set -e

echo "=== Starting Nginx + ModSecurity + CRS Setup ==="

# 1. Install Nginx and ModSecurity dynamic module
echo "Installing Nginx and libnginx-mod-security..."
sudo apt-get update
sudo apt-get install -y nginx libnginx-mod-security git curl

# 2. Configure directory structure
echo "Setting up directories..."
sudo mkdir -p /etc/nginx/modsecurity
sudo mkdir -p /etc/nginx/modsecurity/exceptions
sudo mkdir -p /var/log/modsec

# Create a placeholder conf file to prevent inclusion patterns from failing when no exceptions exist
sudo touch /etc/nginx/modsecurity/exceptions/exception_00_placeholder.conf
echo "# Placeholder exception" | sudo tee /etc/nginx/modsecurity/exceptions/exception_00_placeholder.conf > /dev/null

# Make sure permissions allow Nginx to write logs and local user to read them
sudo chmod -R 777 /var/log/modsec

# 3. Configure core ModSecurity properties
echo "Configuring modsecurity.conf..."
if [ -f "/etc/modsecurity/modsecurity.conf" ]; then
    sudo cp /etc/modsecurity/modsecurity.conf /etc/nginx/modsecurity/modsecurity.conf
elif [ -f "/etc/modsecurity/modsecurity.conf-recommended" ]; then
    sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/nginx/modsecurity/modsecurity.conf
else
    echo "Warning: modsecurity.conf-recommended not found. Downloading raw recommended config..."
    sudo curl -sSLo /etc/nginx/modsecurity/modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended
fi

# Apply custom configurations (DetectionOnly, JSON Audit logs, body parser activation)
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine DetectionOnly/' /etc/nginx/modsecurity/modsecurity.conf 2>/dev/null || true
# Ensure Engine is DetectionOnly (in case default is Off)
sudo sed -i 's/SecRuleEngine Off/SecRuleEngine DetectionOnly/' /etc/nginx/modsecurity/modsecurity.conf
sudo sed -i 's/SecAuditEngine RelevantOnly/SecAuditEngine On/' /etc/nginx/modsecurity/modsecurity.conf
sudo sed -i 's/SecAuditLogParts ABDEFHx/SecAuditLogParts ABCFHIJKZ/' /etc/nginx/modsecurity/modsecurity.conf
sudo sed -i 's|SecAuditLog /var/log/modsec_audit.log|SecAuditLog /var/log/modsec/audit.log|' /etc/nginx/modsecurity/modsecurity.conf
# Enable JSON log format and request/response body parsers
if ! grep -q "SecAuditLogFormat JSON" /etc/nginx/modsecurity/modsecurity.conf; then
    echo -e "\n# Custom configuration added by setup script" | sudo tee -a /etc/nginx/modsecurity/modsecurity.conf > /dev/null
    echo "SecAuditLogFormat JSON" | sudo tee -a /etc/nginx/modsecurity/modsecurity.conf > /dev/null
fi
sudo sed -i 's/SecRequestBodyAccess Off/SecRequestBodyAccess On/' /etc/nginx/modsecurity/modsecurity.conf
sudo sed -i 's/SecResponseBodyAccess Off/SecResponseBodyAccess On/' /etc/nginx/modsecurity/modsecurity.conf

# 4. Clone and configure OWASP Core Rule Set (CRS)
if [ ! -d "/etc/nginx/modsecurity/crs" ]; then
    echo "Cloning OWASP CRS v4..."
    sudo git clone --depth 1 -b v4.0.0 https://github.com/coreruleset/coreruleset.git /etc/nginx/modsecurity/crs
    sudo cp /etc/nginx/modsecurity/crs/crs-setup.conf.example /etc/nginx/modsecurity/crs/crs-setup.conf
else
    echo "OWASP CRS directory already exists at /etc/nginx/modsecurity/crs"
fi

# 5. Create the ModSecurity master entrypoint config
echo "Creating master entrypoint /etc/nginx/modsecurity/main.conf..."
sudo tee /etc/nginx/modsecurity/main.conf > /dev/null <<EOF
# Master ModSecurity Configuration
Include /etc/nginx/modsecurity/modsecurity.conf

# Include CRS Setup
Include /etc/nginx/modsecurity/crs/crs-setup.conf

# Include CRS Rules
Include /etc/nginx/modsecurity/crs/rules/*.conf

# Include Agent-Generated Exception Rules
Include /etc/nginx/modsecurity/exceptions/exception_*.conf
EOF

# 6. Configure Nginx Virtual Host to reverse proxy traffic to local target-app on port 5000
echo "Configuring default Nginx virtual host..."
sudo tee /etc/nginx/sites-available/default > /dev/null <<EOF
server {
    listen 8080 default_server;
    server_name _;

    # Enable ModSecurity
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity/main.conf;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 10s;
        proxy_read_timeout 30s;
    }
}
EOF

# 7. Start and verify Nginx
echo "Testing Nginx configuration..."
sudo nginx -t

echo "Starting and enabling Nginx..."
sudo systemctl enable nginx
sudo systemctl restart nginx

echo "=== Nginx + ModSecurity Setup Complete ==="
echo "Nginx proxy is running on http://localhost:8080 (routing to backend Flask on http://127.0.0.1:5000)"
echo "ModSecurity Audit log: /var/log/modsec/audit.log"
EOF
