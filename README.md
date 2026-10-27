[CertRobo](https://github.com/aliceactually/certrobo)
===========

CertRobo is a standalone Certificate Authority (CA) and certificate issuance portal written using ASP.NET Core 10.0 and Blazor Server.
It manages local users, roles, and domain issuance policies internally, protects its CA signing key at rest, issues RSA and ECDSA leaf certificates, and publishes signed X.509 v2 CRLs without requiring Active Directory or AD CS.

## System requirements

* Linux (RHEL / Rocky Linux 10, Debian/Ubuntu, x86_64 or aarch64), macOS, or Windows Server
* ASP.NET Core 10.0 Runtime (`aspnetcore-runtime-10.0`) and `libicu`
* Reverse proxy such as `nginx` (recommended for Linux production deployments)

---

## Linux Production Deployment Guide (Rocky Linux 10 / RHEL 10)

### 1. Install Runtime and Reverse Proxy Dependencies

```bash
sudo dnf install -y aspnetcore-runtime-10.0 libicu nginx unzip openssl policycoreutils-python-utils
```

> **Note:** On minimal Enterprise Linux installations, `libicu` is not installed by default and is required by .NET for internationalization and IDN/RegionInfo validation.

### 2. Publish and Stage the Application

On your build machine, publish for your target architecture (`linux-x64` or `linux-arm64`) and package without extended attributes:

```bash
dotnet publish CertRobo.csproj -c Release -r linux-arm64 --self-contained false -o ./publish
COPYFILE_DISABLE=1 tar --no-xattrs -czf certrobo-linux.tar.gz -C ./publish .
```

On the target Linux host, create a dedicated unprivileged `certrobo` service user and locked-down directories for binaries (`/opt/certrobo`), persistent state (`/var/lib/certrobo`), and configuration (`/etc/certrobo`):

```bash
sudo useradd --system --home-dir /var/lib/certrobo --create-home --shell /sbin/nologin certrobo
sudo mkdir -p /opt/certrobo /var/lib/certrobo/ca /var/lib/certrobo/dataprotection-keys /var/lib/certrobo/backups /etc/certrobo

sudo tar -xzf /tmp/certrobo-linux.tar.gz -C /opt/certrobo
sudo chown -R root:certrobo /opt/certrobo
sudo chmod -R u=rwX,g=rX,o= /opt/certrobo
sudo chmod 0750 /opt/certrobo/CertRobo
sudo chown -R certrobo:certrobo /opt/certrobo/static /var/lib/certrobo
sudo chmod 0700 /var/lib/certrobo /var/lib/certrobo/ca /var/lib/certrobo/dataprotection-keys /var/lib/certrobo/backups
sudo chown -R root:certrobo /etc/certrobo
sudo chmod 0750 /etc/certrobo
```

### 3. Configure Secret Custody and Environment

Generate a strong passphrase for encrypting CA private keys at rest (`AES-256-CBC`, PBKDF2-SHA256, 100,000 iterations) in a mode-`0600` file owned by `certrobo`:

```bash
sudo sh -c 'umask 077 && openssl rand -base64 32 > /etc/certrobo/ca.pass'
sudo chown certrobo:certrobo /etc/certrobo/ca.pass
sudo chmod 0600 /etc/certrobo/ca.pass
```

Create `/etc/certrobo/certrobo.env` (`0640`, `root:certrobo`):

```ini
ASPNETCORE_ENVIRONMENT=Production
ASPNETCORE_URLS=http://127.0.0.1:5000
CertRobo__DataDirectory=/var/lib/certrobo
CertRobo__CaStorageDirectory=/var/lib/certrobo/ca
CertRobo__CaPassphraseFile=/etc/certrobo/ca.pass
CertRobo__CrlValidityHours=168
```

### 4. Configure SELinux (`Enforcing`) and `systemd` Service

When SELinux is `Enforcing`, label `/opt/certrobo/CertRobo` as `bin_t` so `systemd` can execute it, and enable `httpd_can_network_connect` so Nginx can proxy to Kestrel on `127.0.0.1:5000`:

```bash
sudo semanage fcontext -a -t bin_t '/opt/certrobo/CertRobo'
sudo restorecon -Rv /opt/certrobo /var/lib/certrobo /etc/certrobo
sudo setsebool -P httpd_can_network_connect 1
```

Create `/etc/systemd/system/certrobo.service`:

```ini
[Unit]
Description=CertRobo Standalone Certificate Authority and Issuance Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=certrobo
Group=certrobo
WorkingDirectory=/opt/certrobo
EnvironmentFile=/etc/certrobo/certrobo.env
ExecStart=/opt/certrobo/CertRobo
Restart=on-failure
RestartSec=5
KillSignal=SIGINT
SyslogIdentifier=certrobo

# Sandboxing
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/certrobo /opt/certrobo/static

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now certrobo.service
```

### 5. Bootstrap Initial Administrator and CA Hierarchy

You can complete initial setup either through the browser (`/setup` and `/admin`) or headlessly via the CLI as the `certrobo` user:

```bash
# 1. Optional: inspect legacy settings.xml and import <Defaults> without guessing AD accounts
sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --inspect-legacy-settings static/settings.xml.example --import-defaults'

# 2. Bootstrap the initial Administrator account (locks /setup afterward)
sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --bootstrap-admin admin "<StrongAdminPassword>" "*"'

# 3. Initialize a Root CA and Subordinate Issuing Intermediate CA
sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --init-ca "Contoso Root CA" "root-ca.contoso.com" RSA-4096 3650 "http://pki.contoso.com/ca.crl" "http://pki.contoso.com/ca.crt"'
sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --init-ca "Contoso Issuing Intermediate CA" "issuing-ca.contoso.com" ECDSA-384 1825 "http://pki.contoso.com/ca.crl" "http://pki.contoso.com/ca.crt" --subordinate'
```

### 6. Issue Portal TLS Certificate and Configure Nginx (`:80` AIA/CDP + `:443` Portal)

Per RFC 5280, relying parties fetching AIA (`/ca.crt`) and CDP (`/ca.crl`, `/ca.crl.pem`) must be able to reach those endpoints over plain HTTP (`:80`) without being redirected to HTTPS, while all interactive portal traffic (`/`, `/login`, `/admin`, `/_blazor`) is served over HTTPS (`:443`) with WebSocket upgrade support.

```bash
sudo mkdir -p /etc/pki/nginx/private
sudo chmod 0700 /etc/pki/nginx/private

sudo openssl ecparam -name prime256v1 -genkey -noout -out /etc/pki/nginx/private/server.key
sudo chmod 0600 /etc/pki/nginx/private/server.key
sudo openssl req -new -key /etc/pki/nginx/private/server.key \
  -subj '/C=US/ST=Washington/L=Redmond/O=Contoso Corporation/OU=IT/CN=pki.contoso.com' \
  -addext 'subjectAltName=DNS:pki.contoso.com' \
  -out /tmp/host-tls.csr
sudo chmod 0644 /tmp/host-tls.csr

sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --issue-csr admin /tmp/host-tls.csr /tmp/host-leaf.crt /tmp/host-fullchain.crt'
sudo cp /tmp/host-fullchain.crt /etc/pki/nginx/server.crt
sudo chmod 0644 /etc/pki/nginx/server.crt
sudo rm -f /tmp/host-tls.csr /tmp/host-leaf.crt /tmp/host-fullchain.crt

# Optional: add the CA chain to local system trust
sudo cp /opt/certrobo/static/rootca.crt /etc/pki/ca-trust/source/anchors/certrobo-ca-chain.crt
sudo update-ca-trust
```

Create `/etc/nginx/conf.d/certrobo.conf` (and ensure any default `server` block on port 80 in `/etc/nginx/nginx.conf` is removed, with `map $http_upgrade $connection_upgrade { default upgrade; '' close; }` inside `http {}`):

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Serve public CA chain and CRL endpoints over plain HTTP (RFC 5280)
    location ~ ^/(ca\.crt|rootca\.crt|ca\.crl|ca\.crl\.pem)$ {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    # Redirect interactive portal traffic to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    http2 on;
    server_name _;

    ssl_certificate     /etc/pki/nginx/server.crt;
    ssl_certificate_key /etc/pki/nginx/private/server.key;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         PROFILE=SYSTEM;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
```

Test and start Nginx:

```bash
sudo restorecon -Rv /etc/pki/nginx /etc/nginx
sudo nginx -t
sudo systemctl enable --now nginx.service
```

---

## Reference: Profiles, Policy, Recovery, and Cutover

1. **Supported TLS Server Leaf Profiles**
   * `tls-server-ecdsa-256` (ECDSA P-256, `digitalSignature`, `serverAuth` + `clientAuth`)
   * `tls-server-ecdsa-384` (ECDSA P-384, `digitalSignature`, `serverAuth` + `clientAuth`)
   * `tls-server-rsa-2048` (RSA 2048, `digitalSignature` + `keyEncipherment`, `serverAuth` + `clientAuth`)
   * `tls-server-rsa-4096` (RSA 4096, `digitalSignature` + `keyEncipherment`, `serverAuth` + `clientAuth`)

2. **Domain Policy Rules**
   * Wildcard pattern `*.contoso.com` authorizes any subdomain of `contoso.com` (including wildcard certificates like `*.contoso.com`) as well as the apex domain `contoso.com`.
   * A bare domain like `contoso.com` matches only that exact apex domain.
   * A single `*` allows all valid multi-label DNS domains.

3. **Password Recovery & Break-Glass Reset**
   * Administrators can enable/disable accounts and reset passwords from `/admin`. Disabling an account or resetting its password immediately rotates its `SecurityStamp` and invalidates active sessions.
   * If all administrators are locked out, run from the host CLI:
     ```bash
     sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --reset-admin-password <username> "<newPassword>"'
     ```

4. **Consistent Backup, Restore, and Cutover Notes**
   * `BackupRestoreService` creates a consistent online snapshot (`VACUUM INTO`) of `certrobo.db` together with `ca/*.p8.enc` and `dataprotection-keys/*.xml`. You can download a backup archive from `/admin` or run from the CLI:
     ```bash
     sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --backup /var/lib/certrobo/backups/certrobo-backup.zip'
     sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --restore /var/lib/certrobo/backups/certrobo-backup.zip'
     ```
   * Note that rolling back to an earlier backup after certificates have been delivered to clients cannot undo trust in already-issued certificates; if importing an existing CA identity from AD CS, fence the old signer first, set the initial serial and CRL number floors above the highest previously issued values, and seed any unexpired revoked serials in `/admin`.

## Licence

CertRobo is Copyright © 2022-2026 Alice Kallista Saunier. All rights
reserved. The author gratefully acknowledges the support of Xactly
Corporation in producing and releasing this software.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
