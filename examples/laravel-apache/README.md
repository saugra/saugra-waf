# Laravel + Apache + Saugra WAF Example

This example demonstrates how to deploy Saugra WAF in front of a Laravel application served by Apache httpd / mod_php or php-fpm.

## Architecture Request Flow

```txt
Client (Browser/curl)
  └──> Apache HTTPD (Port 80/443)
         └──> Saugra WAF (Port 8787) [Inspects & Blocks/Monitors]
                └──> Apache / PHP-FPM Laravel App (Port 8080)
```

## Setup & Startup Instructions

### 1. Start Laravel Backend (e.g. php artisan serve or Apache backend virtualhost)
```bash
php artisan serve --host=127.0.0.1 --port=8080
```

### 2. Start Saugra WAF
```bash
saugra-waf run --config examples/laravel-apache/saugra-waf.yml
```

### 3. Configure Apache Reverse Proxy
Place `apache.conf` in `/etc/apache2/sites-available/laravel-saugra.conf` and enable it:
```bash
sudo a2enmod proxy proxy_http headers
sudo a2ensite laravel-saugra
sudo systemctl reload apache2
```

## Testing & Verification Commands

```bash
# 1. Clean Request (Forwarded to Laravel)
curl -i http://localhost/

# 2. XSS Attack (Blocked by Saugra WAF)
curl -i "http://localhost/comment?text=<script>alert(1)</script>"

# 3. SQL Injection Attack (Blocked by Saugra WAF)
curl -i "http://localhost/users?search=%27%20OR%201=1--"

# 4. View Security Logs
saugra-waf logs tail

# 5. Explain Blocked Event
saugra-waf explain <request-id>
```
