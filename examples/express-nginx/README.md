# Node.js/Express + Nginx + Saugra WAF Example

This example demonstrates how to deploy Saugra WAF in front of a Node.js/Express application with Nginx as the reverse proxy.

## Architecture Request Flow

```txt
Client (Browser/curl)
  └──> Nginx (Port 80/443)
         └──> Saugra WAF (Port 8787) [Inspects & Blocks/Monitors]
                └──> Node.js Express App (Port 3000)
```

## Setup & Startup Instructions

### 1. Start Express Application
```bash
node server.js # listening on port 3000
```

### 2. Start Saugra WAF
```bash
saugra-waf run --config examples/express-nginx/saugra-waf.yml
```

### 3. Load Nginx Configuration
Place `nginx.conf` in `/etc/nginx/conf.d/express-saugra.conf` and reload Nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Testing & Verification Commands

```bash
# 1. Clean Request (Forwarded to Express)
curl -i http://localhost/api/health

# 2. Command Injection Attack (Blocked by Saugra WAF)
curl -i "http://localhost/api/exec?cmd=cat%20/etc/passwd"

# 3. SQL Injection Attack (Blocked by Saugra WAF)
curl -i "http://localhost/api/login?username=%27%20OR%201=1--"

# 4. View Security Logs
saugra-waf logs tail

# 5. Explain Blocked Event
saugra-waf explain <request-id>
```
