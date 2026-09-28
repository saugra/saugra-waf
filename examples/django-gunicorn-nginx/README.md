# Django + Gunicorn + Nginx + Saugra WAF Example

This example demonstrates how to deploy Saugra WAF in front of a Django application served by Gunicorn with Nginx as the primary reverse proxy.

## Architecture Request Flow

```txt
Client (Browser/curl)
  └──> Nginx (Port 80/443)
         └──> Saugra WAF (Port 8787) [Inspects & Blocks/Monitors]
                └──> Gunicorn + Django App (Port 8000)
```

## Setup & Startup Instructions

### 1. Start Django with Gunicorn
```bash
gunicorn myproject.wsgi:application --bind 127.0.0.1:8000 --workers 3
```

### 2. Start Saugra WAF
```bash
saugra-waf run --config examples/django-gunicorn-nginx/saugra-waf.yml
```

### 3. Load Nginx Configuration
Place `nginx.conf` in `/etc/nginx/conf.d/django-saugra.conf` and reload Nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Testing & Verification Commands

```bash
# 1. Clean Request (Forwarded to Django)
curl -i http://localhost/

# 2. SQL Injection Attack (Blocked by Saugra WAF)
curl -i "http://localhost/search?q=%27%20OR%201=1--"

# 3. Path Traversal Attack (Blocked by Saugra WAF)
curl -i "http://localhost/download?file=../../../../etc/passwd"

# 4. View Security Logs
saugra-waf logs tail

# 5. Explain Blocked Event
saugra-waf explain <request-id>
```
