#!/bin/bash
# setup_postgres.sh - Locally installs and configures PostgreSQL for the WAF Tuner PoC.
# Target OS: Linux (Ubuntu/Debian)

set -e

echo "=== Starting PostgreSQL Setup ==="

# 1. Install PostgreSQL if not installed
if ! command -v psql &> /dev/null; then
    echo "PostgreSQL not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y postgresql postgresql-contrib
else
    echo "PostgreSQL is already installed."
fi

# 2. Ensure PostgreSQL service is running and enabled
echo "Ensuring postgresql service is active and enabled..."
sudo systemctl enable postgresql
sudo systemctl start postgresql

# 3. Create database user and database matching .env configuration
# Config details:
#   User: waf
#   Password: waf
#   Database: wafdb
echo "Creating database user and schema..."

# Check if role 'waf' exists, create if missing
USER_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='waf'")
if [ "$USER_EXISTS" != "1" ]; then
    echo "Creating role 'waf'..."
    sudo -u postgres psql -c "CREATE USER waf WITH PASSWORD 'waf';"
else
    echo "Role 'waf' already exists."
fi

# Check if database 'wafdb' exists, create if missing
DB_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='wafdb'")
if [ "$DB_EXISTS" != "1" ]; then
    echo "Creating database 'wafdb' owned by 'waf'..."
    sudo -u postgres psql -c "CREATE DATABASE wafdb OWNER waf;"
else
    echo "Database 'wafdb' already exists."
fi

# 4. Import schema from postgres/init.sql
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INIT_SQL="$SCRIPT_DIR/../postgres/init.sql"

if [ -f "$INIT_SQL" ]; then
    echo "Applying schema init.sql to database..."
    PGPASSWORD=waf psql -h localhost -U waf -d wafdb -f "$INIT_SQL"
    echo "Database schema configured successfully."
else
    echo "Error: init.sql not found at $INIT_SQL"
    exit 1
fi

echo "=== PostgreSQL Setup Complete ==="
echo "Connection string: postgresql://waf:waf@localhost:5432/wafdb"
