---
uid: network-reverse-proxy-nginx
title: Nginx
---

## Nginx

"[Nginx](https://www.nginx.com/) (pronounced "engine X") is a web server which can also be used as a reverse proxy, load balancer, mail proxy and HTTP cache. The software was created by Igor Sysoev and first publicly released in 2004.[9] A company of the same name was founded in 2011 to provide support and Nginx plus paid software." - [Wikipedia](https://en.wikipedia.org/wiki/Nginx)

## Nginx from a subdomain (jellyfin.example.org)

Create the file `/etc/nginx/sites-available/jellyfin` which will forward requests to Jellyfin.  After you've finished, you will need to symlink this file to /etc/nginx/sites-enabled and then reload nginx.  This example assumes you've already acquired certifications as documented in our [Let's Encrypt](https://jellyfin.org/docs/general/networking/letsencrypt#nginx) guide.

Note that a server listening on http port 80 is required for the Certbot / Let's Encrypt certificate renewal process.

### HTTPS config example

```config
server {
    # Nginx versions prior to 1.25
    #listen 443 ssl http2;
    #listen [::]:443 ssl http2;

    # Nginx versions 1.25+
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;

    server_name jellyfin.example.org;

    ## The default `client_max_body_size` is 1M, this might not be enough for some posters, etc.
    client_max_body_size 20M;

    # Comment next line to allow TLSv1.0 and TLSv1.1 if you have very old clients
    ssl_protocols TLSv1.3 TLSv1.2;

    ssl_certificate /etc/letsencrypt/live/example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.org/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/example.org/chain.pem;

    # use a variable to store the upstream proxy
    set $jellyfin 127.0.0.1;

    # Security / XSS Mitigation Headers
    add_header X-Content-Type-Options "nosniff";

    # Permissions policy. May cause issues with some clients
    add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), battery=(), bluetooth=(), camera=(), clipboard-read=(), display-capture=(), document-domain=(), encrypted-media=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), keyboard-map=(), local-fonts=(), magnetometer=(), microphone=(), payment=(), publickey-credentials-get=(), serial=(), sync-xhr=(), usb=(), xr-spatial-tracking=()" always;

    # Content Security Policy
    # See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
    # Enforces https content and restricts JS/CSS to origin
    # External Javascript (such as cast_sender.js for Chromecast) must be whitelisted.
    add_header Content-Security-Policy "default-src https: data: blob: ; img-src 'self' https://* ; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://www.gstatic.com https://www.youtube.com blob:; worker-src 'self' blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'self'; font-src 'self'";

    location / {
        # Proxy main Jellyfin traffic
        proxy_pass http://$jellyfin:8096;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Protocol $scheme;
        proxy_set_header X-Forwarded-Host $http_host;

        # Disable buffering when the nginx proxy gets very resource heavy upon streaming
        proxy_buffering off;
    }

    location /socket {
        # Proxy Jellyfin Websockets traffic
        proxy_pass http://$jellyfin:8096;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Protocol $scheme;
        proxy_set_header X-Forwarded-Host $http_host;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name jellyfin.example.org;
    return 301 https://$host$request_uri;
}
```

## Extra Nginx Configurations

### Censor sensitive information in logs

This censors any <code>api_key</code> URL parameter from the logfile.

```conf
#Must be in HTTP block
log_format stripsecrets '$remote_addr $host - $remote_user [$time_local] '
                    '"$secretfilter" $status $body_bytes_sent '
                    '$request_length $request_time $upstream_response_time '
                    '"$http_referer" "$http_user_agent"';

map $request $secretfilter {
    ~*^(?<prefix1>.*[\?&]api_key=)([^&]*)(?<suffix1>.*)$  "${prefix1}***$suffix1";
    default                                               $request;
}

#Must be inside server block
#Insert into all servers where you want filtering (e.g HTTP + HTTPS block)
access_log /var/log/nginx/access.log stripsecrets;
```

## Nginx Proxy Manager

[Nginx Proxy Manager](https://nginxproxymanager.com/) provides an easy-to-use web GUI for Nginx.

Create a proxy host and point it to your Jellyfin server's IP address and http port (usually 8096)

Enable "Block Common Exploits", and "Websockets Support". Configure the access list if you intend to use them. Otherwise leave it on "publicly accessible".

## Extra Nginx Proxy Manager Configurations
### Disabling proxy buffering 
In the "Advanced" tab, enter the following in "Custom Nginx Configuration".  This is optional, but recommended if you intend to make Jellyfin accessible outside of your home.
```config
    # Disable buffering when the nginx proxy gets very resource heavy upon streaming
    proxy_buffering off;
```
### SSL Certificates
In the "SSL" tab, use the jellyfin.example.org certificate that you created with Nginx Proxy Manager and enable "Force SSL", "HTTP/2 Support", "HSTS Enabled", "HSTS Subdomains".

### Security Headers: 
Optional Security headers can be added to Jellyfin, it is highly recommended to test these settings to ensure they are properly working for your instance of Jellyfin.
Jellyfin out of the box does not contain Content-Security-Policy headers, using online scanning tools such as the [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) scanning tool Jellyfin will return a `C+/B` rating depending on your configuration with a warning about missing headers, Nginx Proxy Manager can be used to add these headers for an `A+` rating. 

In your Jellyfin Proxy host, navigate to "Custom locations" section and add a location. 
The location should be `/`, the Forward Host name IP is your jellyfin servers IP address and port (usually 8096). 
Click the gear icon next to the location block, this will open up an advanced option to allow headers to be set.

Here is an example of headers that are added: 
```
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; media-src 'self' blob:; img-src 'self'; worker-src 'self' blob:; frame-ancestors 'self';" always;
```
Save and verify that your Jellyfin is working and accessible. 

If you are using Custom CSS you will need to add the URL for the CSS into the CSP header like such: 

```
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/npm/jellyskin@latest/dist/main.css https://cdn.jsdelivr.net/npm/jellyskin@latest/dist/logo.css https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; media-src 'self' blob:; img-src 'self'; worker-src 'self' blob:; frame-ancestors 'self';" always;
```
As always, save and verify that your Jellyfin instance is working and accessible, ensure content loads as expected. 

