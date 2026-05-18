#!/usr/bin/env bash
# ============================================================
# ICEBERG LC — One-shot VPS setup script
# Run as root on a fresh Ubuntu 22.04 server:
#   curl -sSL https://raw.githubusercontent.com/YOUR_ORG/College-ERP/main/deploy/setup.sh | sudo bash
# ============================================================
set -euo pipefail

DOMAIN="iceberglc.com"
APP_USER="iceberg"
APP_DIR="/home/$APP_USER/College-ERP"
REPO="https://github.com/Jahongir359/College-ERP.git"   # update if needed
PYTHON="python3.11"

echo "▶  Updating system packages…"
apt-get update -qq && apt-get upgrade -y -qq

echo "▶  Installing dependencies…"
apt-get install -y -qq \
    nginx certbot python3-certbot-nginx \
    python3.11 python3.11-venv python3.11-dev \
    postgresql postgresql-contrib \
    git curl build-essential libpq-dev

echo "▶  Creating app user…"
id -u "$APP_USER" &>/dev/null || useradd -m -s /bin/bash "$APP_USER"

echo "▶  Cloning repository…"
su - "$APP_USER" -c "
  git clone $REPO $APP_DIR 2>/dev/null || (cd $APP_DIR && git pull)
  cd $APP_DIR
  $PYTHON -m venv venv
  venv/bin/pip install -q --upgrade pip
  venv/bin/pip install -q -r requirements.txt
"

echo "▶  Setting up .env — EDIT THIS FILE before starting the service!"
if [ ! -f "$APP_DIR/.env" ]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
    # Generate a random secret key
    SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    sed -i "s|change-me-to-a-long-random-string|$SECRET|" "$APP_DIR/.env"
    sed -i "s|DJANGO_DEBUG=True|DJANGO_DEBUG=False|" "$APP_DIR/.env"
    sed -i "s|DJANGO_ALLOWED_HOSTS=|DJANGO_ALLOWED_HOSTS=$DOMAIN,www.$DOMAIN|" "$APP_DIR/.env"
    echo ""
    echo "⚠  Edit $APP_DIR/.env and set:"
    echo "     DATABASE_URL, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD"
    echo "   Then run: sudo systemctl start gunicorn-iceberg"
fi

echo "▶  Running Django setup…"
su - "$APP_USER" -c "
  cd $APP_DIR
  venv/bin/python manage.py migrate --noinput
  venv/bin/python manage.py collectstatic --noinput -v 0
"

echo "▶  Installing systemd service…"
cp "$APP_DIR/deploy/gunicorn.service" /etc/systemd/system/gunicorn-iceberg.service
systemctl daemon-reload
systemctl enable gunicorn-iceberg

echo "▶  Configuring Nginx…"
cp "$APP_DIR/deploy/nginx.conf" /etc/nginx/sites-available/iceberglc
ln -sf /etc/nginx/sites-available/iceberglc /etc/nginx/sites-enabled/iceberglc
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo "▶  Obtaining SSL certificate…"
certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos \
    --email admin@iceberglc.com --redirect

echo "▶  Starting Gunicorn…"
systemctl start gunicorn-iceberg

echo ""
echo "✅  Setup complete! Visit https://$DOMAIN"
echo "    Gunicorn status: sudo systemctl status gunicorn-iceberg"
echo "    Nginx status:    sudo systemctl status nginx"
echo "    App logs:        sudo journalctl -u gunicorn-iceberg -f"
