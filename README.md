[CertRobo](https://github.com/aliceactually/certrobo)
===========

CertRobo is a standalone Certificate Authority (CA) and certificate issuance portal written using ASP.NET Core 10.0 and Blazor Server.
It manages local users, roles, and domain issuance policies internally, protects its CA signing key at rest, issues RSA and ECDSA leaf certificates, and publishes signed X.509 v2 CRLs without requiring Active Directory or AD CS.

## System requirements

* Linux (Rocky Linux 10 / RHEL 10 or Ubuntu 26.04 LTS, `x86_64` or `aarch64`), macOS, or Windows Server
  *(Note: Linux deployment procedures below were live-verified on Rocky Linux 10.2 and Ubuntu 26.04.1 LTS on both `x86_64` and `aarch64`; standalone Debian was not separately validated.)*
* ASP.NET Core 10.0 Runtime (`aspnetcore-runtime-10.0`) and ICU globalization libraries (`libicu` on Rocky/RHEL; installed automatically as a runtime dependency on Ubuntu 26.04)
* Reverse proxy such as `nginx` (recommended for Linux production deployments)

---

## Linux Production Deployment Guide (Rocky Linux 10 & Ubuntu 26.04 LTS)

### 1. Install Runtime and Reverse Proxy Dependencies

**Rocky Linux 10 / RHEL 10 (`x86_64` or `aarch64`):**

```bash
sudo dnf install -y aspnetcore-runtime-10.0 libicu nginx unzip openssl policycoreutils-python-utils
```

> **Note:** On minimal Enterprise Linux installations, `libicu` is not installed by default and is required by .NET for internationalization and IDN/RegionInfo validation.

**Ubuntu 26.04 LTS (`x86_64` or `aarch64`):**

```bash
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y aspnetcore-runtime-10.0 nginx unzip openssl ca-certificates
```

> **Note:** On Ubuntu 26.04 LTS, the versioned ICU library package is pulled in automatically as a dependency of `dotnet-runtime-10.0` (there is no unversioned `libicu` apt package).

### 2. Publish, Transfer, and Stage the Application

On your build machine, publish outside the source tree into a clean architecture-specific output directory (`linux-x64` for `x86_64` hosts or `linux-arm64` for `aarch64` hosts), package without macOS/extended attributes, and copy the archive to `/tmp/certrobo-linux.tar.gz` on the target host. Keeping build outputs outside the source tree prevents a later publish from bundling the other architecture's output as application content:

```bash
# For x86_64 target hosts (uname -m -> x86_64):
rm -rf ../certrobo-publish/linux-x64
dotnet publish CertRobo.csproj -c Release -r linux-x64 --self-contained false -o ../certrobo-publish/linux-x64
COPYFILE_DISABLE=1 tar --no-xattrs -czf ../certrobo-publish/certrobo-linux-x64.tar.gz -C ../certrobo-publish/linux-x64 .
scp ../certrobo-publish/certrobo-linux-x64.tar.gz <user>@<target-host>:/tmp/certrobo-linux.tar.gz

# For ARM64 target hosts (uname -m -> aarch64):
rm -rf ../certrobo-publish/linux-arm64
dotnet publish CertRobo.csproj -c Release -r linux-arm64 --self-contained false -o ../certrobo-publish/linux-arm64
COPYFILE_DISABLE=1 tar --no-xattrs -czf ../certrobo-publish/certrobo-linux-arm64.tar.gz -C ../certrobo-publish/linux-arm64 .
scp ../certrobo-publish/certrobo-linux-arm64.tar.gz <user>@<target-host>:/tmp/certrobo-linux.tar.gz
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

Create `/etc/certrobo/certrobo.env` and set ownership to `root:certrobo` with mode `0640`:

```bash
sudo tee /etc/certrobo/certrobo.env >/dev/null <<'EOF'
ASPNETCORE_ENVIRONMENT=Production
ASPNETCORE_URLS=http://127.0.0.1:5000
CertRobo__DataDirectory=/var/lib/certrobo
CertRobo__CaStorageDirectory=/var/lib/certrobo/ca
CertRobo__CaPassphraseFile=/etc/certrobo/ca.pass
CertRobo__PublicBaseUrl=http://pki.contoso.com
CertRobo__CrlValidityHours=168
EOF
sudo chown root:certrobo /etc/certrobo/certrobo.env
sudo chmod 0640 /etc/certrobo/certrobo.env
```

> **Custody Model:** CertRobo enforces a single shared at-rest CA storage passphrase across the active issuer, any maintained historical issuers (whose CRLs must continue to be refreshed until expiry), and any pending external-CA request.
> * When persistent custody is configured (`CertRobo__CaPassphraseFile`, `CERTROBO_CA_PASSPHRASE`, or `CertRobo__CaPassphrase`), initial CA creation, import, replacement, and runtime unlock must match the configured secret.
> * When no persistent passphrase is configured (manual-unlock mode), the CA starts **Locked** after every service restart until an administrator unlocks it in `/admin`.
> * When importing an existing CA from an encrypted PEM key or PKCS#12 (`.pfx`/`.p12`) bundle, the bundle's import decryption password may differ from CertRobo's at-rest CA storage passphrase.

### 4. Configure Platform MAC (SELinux / AppArmor) and `systemd` Service

**Rocky Linux 10 / RHEL 10 only (SELinux `Enforcing`):**
Label `/opt/certrobo/CertRobo` as `bin_t` so `systemd` can execute it, and enable `httpd_can_network_connect` so Nginx can proxy to Kestrel on `127.0.0.1:5000`:

```bash
sudo semanage fcontext -a -t bin_t '/opt/certrobo/CertRobo'
sudo restorecon -Rv /opt/certrobo /var/lib/certrobo /etc/certrobo
sudo setsebool -P httpd_can_network_connect 1
```

*(On Ubuntu 26.04 LTS, AppArmor is used instead of SELinux; skip the `semanage`, `restorecon`, and `setsebool` commands above.)*

Create `/etc/systemd/system/certrobo.service` (valid on both Rocky Linux 10 and Ubuntu 26.04 LTS; `UMask=0077` ensures any newly created SQLite database, WAL/SHM, and key files are created with private `0600` permissions):

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
UMask=0077
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

### 5A. Externally Signed Issuing CA

CertRobo can generate and retain an encrypted Issuing CA key locally while an external parent CA signs its PKCS #10 request. This supports initial setup and replacement; during replacement, the current CA continues issuing until the validated replacement is explicitly activated.

In **Administration → Certificate authority**, choose:

1. **Generate Self-Signed Root CA** for a standalone trust hierarchy.
2. **Import Existing Issuing CA** when certificate and private key material already exist.
3. **Request Issuing CA from External CA** to generate the key and CSR inside CertRobo.

For the third path:

1. Choose the RSA/ECDSA key parameters and create the pending request.
2. Download the existing `.csr`. Repeated downloads, page refreshes, and restarts return the same CSR and do not regenerate its key.
3. Have the parent CA issue a subordinate CA certificate. Supply the signed certificate and complete parent/root chain as PEM, DER, or certificate-only PKCS #7/P7B.
4. Review the validated subject, issuer, SHA-256 fingerprint, validity, authoritative KeyUsage/path-length, name/EKU constraints, and ordered chain.
5. Explicitly activate it. A failed upload or cancellation does not replace the active CA.

The equivalent headless flow is:

```bash
sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --request-external-ca "Contoso Issuing CA" "issuing-ca.contoso.com" ECDSA-384 /tmp/issuing-ca.csr'

# After the parent returns the signed certificate and chain:
sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --complete-external-ca /tmp/issuing-ca.crt /tmp/parent-chain.p7b'
```

#### Parent CA Requirements

The parent must return a currently valid subordinate CA certificate whose public key matches the CSR, with:

* critical `BasicConstraints: CA=true`;
* `KeyUsage` containing both `keyCertSign` and `cRLSign`;
* a complete, cryptographically valid path to an explicitly supplied self-signed trust anchor;
* sufficient `pathLenConstraint` to permit this Issuing CA; and
* no critical restrictions CertRobo cannot safely enforce.

Returned permissions are authoritative. CertRobo enforces supported DNS NameConstraints and EKU restrictions on subsequent leaf issuance and rejects unsupported NameConstraints forms or critical extensions. Leaf validity is bounded by the earliest expiry and latest start date across the complete usable issuing chain, including the trust anchor. Operational policy is therefore that an expired trust anchor stops new issuance even if the Issuing CA certificate itself remains valid.

#### Optional Microsoft AD CS CES Connector

The pending-request view can optionally submit the same local CSR to Microsoft **Certificate Enrollment Web Service (CES)** using HTTPS and [MS-WSTEP]. It does not use LDAP, domain membership, GPO, `/certsrv` page scraping, or Windows-only enrollment APIs.

Configure the direct `service.svc/CES` HTTPS endpoint, certificate template name, bounded timeout, and one authentication mode:

* **Username/password**: sent as a WS-Security UsernameToken (`PasswordText`) inside the SOAP 1.2 request, not HTTP Basic authentication. The account needs only the CA/template enrollment permissions required by your policy.
* **TLS client certificate**: optional; configure a matching certificate/private key accepted by the CES endpoint.

Connector passwords/client private keys are encrypted with the persisted ASP.NET Core Data Protection key ring. `CERTROBO_ADCS_CES_PASSWORD` may supply a runtime-only username/password secret instead. For an internally issued CES HTTPS certificate, configure the internal self-signed Root CA and any required intermediates as **Custom Server TLS Trust**. Hostname and chain validation remain mandatory; there is no skip-validation option and redirects are refused.

The AD CS certificate template should:

* be published on the target Enterprise CA and permit the connector account to enroll;
* use **Supply in the request** for the subject when the submitted PKCS #10 subject is authoritative;
* issue a subordinate CA certificate with `BasicConstraints CA=true`, `keyCertSign`, and `cRLSign`;
* set a path-length compatible with CertRobo's requested role; and
* either issue immediately or use normal CA manager approval.

CES outcomes are persisted as issued, pending approval, denied, authentication failure, transport failure, or submission outcome uncertain. Pending requests can be retrieved with WSTEP `QueryTokenStatus` when CES supplies/accepts the AD CS Request ID. After a timeout or connection loss following transmission, CertRobo does not automatically resubmit because the CA might already have accepted the request; reconcile by Request ID or use manual completion.

Manual completion remains available whenever CES is disabled, unavailable, denied, or cannot retrieve a pending request.

### 6. Issue Portal TLS Certificate and Configure Nginx (`:80` AIA/CDP + `:443` Portal)

Per RFC 5280, relying parties fetching AIA (`/issuer.crt` or `/authorities/{id}/issuer.crt`) and CDP (`/ca.crl` or `/authorities/{id}/ca.crl`) must be able to reach those endpoints over plain HTTP (`:80`) without being redirected to HTTPS, while all interactive portal traffic (`/`, `/login`, `/admin`, `/_blazor`) is served over HTTPS (`:443`) with WebSocket upgrade support.

Issue the Nginx TLS server certificate and TLS server chain (`--issue-csr <user> <csrPath> <outCertPath> [<outTlsServerChainPath>]` writes the leaf plus intermediate CA(s) without the self-signed Root CA to `<outTlsServerChainPath>`; pass `--root-out <path>` or `--fullchain-out <path>` if you also want the Root CA or complete chain written out, or use `--export-issued <serialHex> <outCertPath> [<outTlsServerChainPath>]` to recover outputs for an already-issued certificate):

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

sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --issue-csr admin /tmp/host-tls.csr /tmp/host-leaf.crt /tmp/host-tlschain.crt --root-out /tmp/host-rootca.crt'
sudo cp /tmp/host-tlschain.crt /etc/pki/nginx/server.crt
sudo chmod 0644 /etc/pki/nginx/server.crt
sudo rm -f /tmp/host-tls.csr /tmp/host-leaf.crt /tmp/host-tlschain.crt
```

Optional: add the Root CA trust anchor to the local host trust store:

```bash
# Rocky Linux 10 / RHEL 10:
sudo cp /tmp/host-rootca.crt /etc/pki/ca-trust/source/anchors/certrobo-rootca.crt
sudo update-ca-trust
sudo rm -f /tmp/host-rootca.crt

# Ubuntu 26.04 LTS:
sudo cp /tmp/host-rootca.crt /usr/local/share/ca-certificates/certrobo-rootca.crt
sudo update-ca-certificates
sudo rm -f /tmp/host-rootca.crt
```

#### Resolve Default Port 80 `default_server` Conflicts Before Adding `certrobo.conf`

Nginx allows only one `default_server` listener per IP/port pair:
* **On Rocky Linux 10 / RHEL 10:** `/etc/nginx/nginx.conf` ships with a built-in `server { listen 80; listen [::]:80; ... }` block inside `http {}`. On a dedicated CertRobo host, comment out or remove that built-in `server { ... }` block (`sudo sed -i '/^    server {/,/^    }/s/^/#/' /etc/nginx/nginx.conf`) so `/etc/nginx/conf.d/certrobo.conf` can bind `listen 80 default_server;`.
* **On Ubuntu 26.04 LTS:** `/etc/nginx/nginx.conf` includes both `/etc/nginx/conf.d/*.conf` and `/etc/nginx/sites-enabled/*`. On a dedicated CertRobo host, remove the stock `/etc/nginx/sites-enabled/default` symlink (`sudo rm -f /etc/nginx/sites-enabled/default`)—or, if the host serves other virtual hosts, remove `default_server` from the competing site configuration—before testing Nginx.

Create `/etc/nginx/conf.d/certrobo.conf` (compatible with both Rocky Linux 10 and Ubuntu 26.04 LTS OpenSSL builds):

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Serve public CA chain and CRL endpoints over plain HTTP (RFC 5280)
    location ~ ^/(ca\.crt|ca\.p7b|issuer\.crt|rootca\.crt|ca\.crl|ca\.crl\.pem|authorities/[0-9]+/(ca\.(crt|p7b|crl|crl\.pem)|issuer\.crt))$ {
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
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

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

Test and start/reload Nginx:

```bash
# Rocky Linux 10 / RHEL 10 only (relabel TLS certificate files for SELinux):
sudo restorecon -Rv /etc/pki/nginx /etc/nginx

# Both Rocky Linux 10 and Ubuntu 26.04 LTS:
sudo nginx -t
sudo systemctl enable --now nginx.service
sudo systemctl reload nginx.service
```

---

## Optional OpenID Connect (OIDC) Federated Sign-In (Okta & Generic OIDC)

CertRobo supports optional, provider-agnostic **OpenID Connect (OIDC)** federated sign-in using the OAuth 2.0 Authorization Code flow with PKCE (`S256`) while keeping standalone local authentication and a break-glass local `Administrator` account available at all times.

* **Provider-Agnostic Protocol:** Works with any standard OpenID Connect identity provider (Okta, Microsoft Entra ID, Keycloak, Auth0, Google, Pocket ID, etc.) without Active Directory, LDAP, provider-specific management API tokens, or hardcoded vendor assumptions.
* **Zero Implicit Access:** Valid OIDC authentication never grants CA administration or certificate-issuance rights by itself. An external user is permitted to sign in only when at least one validated group claim from the identity provider matches an explicit administrator-configured mapping in CertRobo (`Administrator` or `Issuer`) and server-side domain/profile policy.
* **Strict External Identity Resolution:** External accounts are identified strictly by the validated `(Issuer, Subject)` pair (`iss` + standard OIDC `sub` claim from the validated ID token), never by email address, display name, preferred username, or mutable/custom claims. CertRobo never automatically links an external OIDC login to a local account sharing the same email or username.

### 1. Configure Your Identity Provider (Okta Example & Generic OIDC)

#### Okta OIDC Web Application (Org Authorization Server)

Ordinary Okta SSO works directly with the built-in **Okta Org Authorization Server** (`https://<your-okta-domain>`) and does **not** require a paid Okta API Access Management custom authorization server, an Okta API token, or AD/LDAP integration. (A custom authorization server such as `https://<your-okta-domain>/oauth2/default` also works if you choose to use one, provided `CertRobo__Oidc__Issuer` and `CertRobo__Oidc__Authority` match that server's exact `issuer` URI.)

1. **Create the OIDC Web Application:**
   * In the Okta Admin Console, go to **Applications → Applications → Create App Integration**.
   * Sign-in method: **OIDC - OpenID Connect**.
   * Application type: **Web Application**.
   * Grant type: **Authorization Code** (PKCE `S256` is automatically negotiated by CertRobo).
   * **Sign-in redirect URIs:** `https://pki.contoso.com/signin-oidc` *(must match `CertRobo__Oidc__PublicCallbackUrl` exactly)*.
   * **Sign-out redirect URIs:** `https://pki.contoso.com/signout-callback-oidc` *(required only if `CertRobo__Oidc__EnableIdpSignOut=true`)*.
   * **Assignments:** Assign the application to the specific Okta groups that should be allowed to use CertRobo (for example, `CertRobo-Admins` and `CertRobo-Issuers`).
2. **Configure the `groups` Claim on the ID Token:**
   * Open the application's **Sign On** tab → **OpenID Connect ID Token** section → **Edit**.
   * Set **Groups claim type** to **Filter** (or **Expression**), claim name `groups`, and match your CertRobo groups (for example, `Starts with` `CertRobo-` or `Matches regex` `^(CertRobo-Admins|CertRobo-Issuers)$`).
   * Save. When using the Okta Org Authorization Server, Okta includes the `groups` claim in the **ID token** (or in the `/userinfo` response when `CertRobo__Oidc__GetClaimsFromUserInfoEndpoint=true`).
3. **Record the Client Credentials and Issuer:**
   * Copy the **Client ID** and **Client Secret**.
   * For the Okta Org Authorization Server, both `Issuer` and `Authority` are your exact Okta org URL without a trailing slash (e.g., `https://contoso.okta.com`). Verify by checking `https://contoso.okta.com/.well-known/openid-configuration` and confirming the `"issuer"` field.

#### Other OpenID Connect Providers

For any other OIDC provider:
* Configure an Authorization Code + PKCE (`S256`) confidential Web client with redirect URI `https://<certrobo-host>/signin-oidc`.
* Set `CertRobo__Oidc__Issuer` and `CertRobo__Oidc__Authority` to the exact `"issuer"` URI advertised in `/.well-known/openid-configuration`.
* If your provider uses a different claim name for groups (for example, `roles` or `directory_groups`), set `CertRobo__Oidc__GroupClaimType`. External account identity is always bound to the standard OIDC `sub` claim in the validated ID token (`CertRobo__Oidc__SubjectClaimType` must be `sub`). If group claims are returned from the UserInfo endpoint instead of the ID token, set `CertRobo__Oidc__GetClaimsFromUserInfoEndpoint=true`.

### 2. Configure CertRobo OIDC Custody and Trusted Reverse Proxy Boundaries

Store the OIDC client secret in a mode-`0600` file owned by `certrobo` (never commit secrets into `appsettings.json`):

```bash
sudo sh -c 'umask 077 && printf "%s" "<YourOidcClientSecret>" > /etc/certrobo/oidc.secret'
sudo chown certrobo:certrobo /etc/certrobo/oidc.secret
sudo chmod 0600 /etc/certrobo/oidc.secret
```

Add the OIDC and reverse-proxy settings to `/etc/certrobo/certrobo.env`:

```bash
# Trusted Reverse Proxy Boundary (defaults to loopback 127.0.0.1 and ::1)
# If Nginx runs on a separate proxy host or container network, list its exact IP or CIDR:
CertRobo__ReverseProxy__KnownProxies__0=127.0.0.1
CertRobo__ReverseProxy__KnownProxies__1=::1
CertRobo__ReverseProxy__ForwardLimit=1

# OpenID Connect Federated Sign-In
CertRobo__Oidc__Enabled=true
CertRobo__Oidc__DisplayName=Okta SSO
CertRobo__Oidc__DefaultLoginMode=Local
CertRobo__Oidc__Issuer=https://contoso.okta.com
CertRobo__Oidc__Authority=https://contoso.okta.com
CertRobo__Oidc__ClientId=<YourOidcClientId>
CertRobo__Oidc__ClientSecretFile=/etc/certrobo/oidc.secret
CertRobo__Oidc__PublicCallbackUrl=https://pki.contoso.com/signin-oidc
CertRobo__Oidc__SignedOutCallbackPath=/signout-callback-oidc
CertRobo__Oidc__EnableIdpSignOut=false
CertRobo__Oidc__GetClaimsFromUserInfoEndpoint=false
CertRobo__Oidc__GroupClaimType=groups
CertRobo__Oidc__SubjectClaimType=sub
CertRobo__Oidc__PreferredUsernameClaimType=preferred_username
CertRobo__Oidc__EmailClaimType=email
CertRobo__Oidc__DisplayNameClaimType=name
CertRobo__Oidc__MaxSessionLifetimeMinutes=60
CertRobo__Oidc__SessionRevalidationSeconds=10

# Optional one-time initial group mappings (imported into SQLite once; live UI/CLI changes are authoritative across restarts):
# Format: GroupName=Role:DomainPattern1,DomainPattern2@AllowedProfileId;...
CertRobo__Oidc__GroupMappingsSpec=CertRobo-Admins=Administrator:*;CertRobo-Issuers=Issuer:*.contoso.com,contoso.com@*
```

> **Reverse Proxy & HTTPS Callback Requirement:** CertRobo requires the OIDC callback (`/signin-oidc`) to arrive over HTTPS (or through an explicitly trusted reverse proxy listed in `CertRobo__ReverseProxy__KnownProxies` / `CertRobo__ReverseProxy__KnownNetworks` that sets `X-Forwarded-Proto: https`). `X-Forwarded-Proto` headers from untrusted client IPs are ignored, and plain-HTTP OIDC callbacks are rejected.

### 3. Granting and Removing Group Access, Policy Precedence, and Login Presentation (UI and CLI)

Administrators control which external IdP groups map to CertRobo roles (`Administrator` or `Issuer`), which DNS domain patterns and certificate profiles each group may request, and how the `/login` page presents local versus federated sign-in:

* **Durable Database Precedence Over Bootstrap Config:** Any `CertRobo__Oidc__GroupMappings` / `CertRobo__Oidc__GroupMappingsSpec` entries in configuration are imported into SQLite **once** (tracked by the persisted `HasSeededConfiguredGroupMappings` marker in `OidcPortalSettings`). Subsequent additions, role changes, domain-rule deletions, or group removals made in `/admin` or via the CLI are authoritative in SQLite and are never overwritten or resurrected across process restarts or backup/restore.
* **Local vs. External Policy Precedence:** External OIDC users derive their domain and profile permissions exclusively from the explicit union of their currently mapped external group rules (`SubjectType = "ExternalGroup"`) and any direct account rules (`SubjectType = "User"`) assigned to their external user ID. Ordinary local role rules (`SubjectType = "Role"`) apply only to local accounts and never widen an external group's domain or profile restrictions.
* **Sign-In Page Presentation (`ProviderDisplayName` & `DefaultLoginMode`):** In **Administration → Users and permissions → Sign-In Page Presentation & Default Emphasis**, administrators can customize the OIDC provider button label (e.g., `Okta SSO`) and choose whether **Local Account Primary** (`Local`) or **Federated OIDC Primary** (`Oidc`) is emphasized first on `/login`. Both sign-in methods always remain rendered on `/login` so local break-glass sign-in is reachable during an IdP outage.
* **In the Web Portal (`/admin`):**
  1. Sign in as an `Administrator` and open **Administration → Users and permissions**.
  2. In **OpenID Connect (OIDC) Federated Sign-In & Group Mappings**, click **+ Add / Update Group Mapping**.
  3. Enter the exact external group claim value (e.g., `CertRobo-Issuers`), choose the role (`Issuer` or `Administrator`), select the allowed certificate profile (`*` or a specific profile such as `tls-server-ecdsa-256`), and enter comma-separated domain patterns (e.g., `*.contoso.com, contoso.com`).
  4. To revoke a group's access, click **Remove Group Mapping** (or remove individual domain rules with `×`). Removing a group mapping immediately strips the role from affected external accounts and rotates their `SecurityStamp`.
* **Via the Host CLI:**
  ```bash
  # Grant or update a group mapping:
  sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --add-oidc-group-mapping "CertRobo-Issuers" Issuer "*.contoso.com,contoso.com" "*"'

  # Remove a group mapping and immediately invalidate affected external sessions:
  sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --remove-oidc-group-mapping "CertRobo-Issuers"'
  ```

### 4. Session Lifecycle, Group Removal, Local Kill Switch, and Sign-Out Behavior

* **Architectural Bound on IdP-Side Changes:** Standard OIDC authorization-code login validates the user's ID token and group claims at sign-in time; an external identity provider does not push real-time group-removal events into an already-established local cookie or Blazor WebSocket circuit. To bound this window:
  1. External OIDC sessions enforce an explicit, non-sliding maximum lifetime (`CertRobo__Oidc__MaxSessionLifetimeMinutes`, default `60` minutes). Once this window elapses, both HTTP requests and active Blazor Server circuits require a fresh OIDC authentication round-trip.
  2. Both the HTTP cookie validator (`SecurityStampValidator`) and the Blazor Server circuit revalidator (`RevalidatingIdentityAuthenticationStateProvider`) re-check the user's `SecurityStamp`, disabled status, session expiry, and active CertRobo group mappings every `CertRobo__Oidc__SessionRevalidationSeconds` (default `10` seconds).
  3. Every certificate issuance request (`IssuancePolicyService`) and administrative action re-verifies the database account status, `SecurityStamp`, and active group/domain mappings on the server at the moment of the action.
* **Administrator-Initiated Local Kill Switch (Immediate Revocation of Access):**
  When an operator removes a user from an IdP group or suspends them in the IdP and needs to terminate their CertRobo session immediately without waiting for `MaxSessionLifetimeMinutes`:
  * **Disable the account in `/admin`:** Click **Disable Account** on the user's row in **Administration → Users and permissions**. This immediately blocks certificate issuance, invalidates active HTTP cookies and Blazor circuits within seconds, and prevents future OIDC sign-ins for that `(issuer, sub)`.
  * **Invalidate active sessions without disabling:** Click **Invalidate Active Sessions** on a specific user or **Invalidate All External Sessions** in **Administration → Users and permissions**, or run from the CLI:
    ```bash
    # Invalidate all active external OIDC sessions:
    sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --invalidate-external-sessions'

    # Invalidate a specific user's active sessions:
    sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --invalidate-external-sessions <userNameOrId>'
    ```
* **Sign-Out Behavior (`EnableIdpSignOut`):**
  * Clicking **Sign Out** in CertRobo (`POST /account/logout`) always terminates the local CertRobo session cookie (`CertRobo.Auth`).
  * By default (`CertRobo__Oidc__EnableIdpSignOut=false`), signing out ends only the local CertRobo session and returns to `/login`, leaving the user's separate browser session at the upstream IdP (e.g., Okta dashboard) intact.
  * If you want CertRobo sign-out to also trigger OIDC RP-Initiated Logout at the identity provider's `end_session_endpoint`, set `CertRobo__Oidc__EnableIdpSignOut=true` and register `https://<certrobo-host>/signout-callback-oidc` as a Sign-out Redirect URI in your IdP application.

### 5. Migration, Rollback, and Break-Glass Local Administrator Recovery

* **Sole Local Administrator Invariant & Password Recovery:** CertRobo enforces at the service boundary that at least one enabled local `Administrator` account with a local password hash remains active at all times (attempts to disable, demote, or delete the last active local `Administrator` are refused even if external OIDC administrators exist). Note that having an enabled local administrator account in the database does not prove an operator knows its current password: if the password is lost or locked out, an OS-authorized operator with host access can always reset it via the CLI (`./CertRobo --reset-admin-password <username> "<newPassword>"`).
* **Rollback to Local-Only Authentication:** To disable federated login at any time, set `CertRobo__Oidc__Enabled=false` in `/etc/certrobo/certrobo.env` and restart `certrobo.service`. Existing external sessions are immediately rejected upon disablement, while local accounts, CA keys, issued certificates, and CRLs continue operating normally.
* **Verification Scope:** This repository's automated test suite (`Tests/CertRobo.Tests/OidcFederatedLoginTests.cs`) exercises the complete ASP.NET Core OpenID Connect authorization-code + PKCE (`S256`) flow against a local RSA-signed OIDC discovery/JWKS/token/userinfo fixture (covering valid sign-in, signature/issuer/audience/lifetime/nonce/state rejection, strict `(issuer, sub)` identity binding and non-`sub` claim collision isolation, durable group-mapping precedence across CLI restarts and backup/restore, sole-local-admin protection and stale circuit actor rejection, local role-rule isolation from external accounts, group removal, account disablement, session/circuit revalidation, local kill switch, login presentation/emphasis settings, safe redirects, trusted proxy boundaries, and secret/token non-exposure in logs). Live enrollment and testing against a production or preview Okta tenant require separate operator authorization and credentials.

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
   * `BackupRestoreService` creates a consistent online snapshot (`VACUUM INTO`) of `certrobo.db` together with `ca/*.p8.enc` and `dataprotection-keys/*.xml`. This includes pending external-enrolment records, pending encrypted keys, non-secret WSTEP continuation data, encrypted connector credentials, and the Data Protection keys needed to recover those credentials. The state backup ZIP itself is **not** encrypted as a whole and contains sensitive application state (the Identity database, Data Protection keys, and encrypted CA keys): protect the archive at rest and in transit. The archive does **not** contain `/etc/certrobo/ca.pass` or `certrobo.env`: back up the CA passphrase securely and separately, along with the configuration needed to restore it. The original passphrase is required to unlock its encrypted signing keys. You can download a backup archive from `/admin` or run from the CLI:
     ```bash
     sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --backup /var/lib/certrobo/backups/certrobo-backup.zip'
     ```
   * **Optional Root CA PKCS#12 in Administrator State Backup (`/admin` UI):** In **Administration → Settings and maintenance → Consistent State Backup**, an authenticated Administrator can explicitly opt in to including a portable PKCS#12 bundle (`ca-pkcs12/root-ca-<id>-<name>.p12`) for a selected locally managed Root CA inside the state backup ZIP. When enabled, CertRobo requires CA key custody to be unlocked, encrypts the PKCS#12 private key and certificate bags using `PBES2-PBKDF2-HMAC-SHA256` with `AES-256-CBC` and a PKCS#12 `HMAC-SHA256` integrity MAC (100,000 iterations), and protects it with a freshly generated 7-word passphrase sampled independently and uniformly with replacement from the EFF long wordlist (`Resources/Passphrases/eff_large_wordlist.txt`, CC BY 4.0 Electronic Frontier Foundation) separated by `-`. The generated passphrase is displayed once in the UI for separate storage and is never logged, persisted, or written inside the ZIP. It protects only the extra `.p12` artifact and does **not** replace the CA storage passphrase required to unlock or restore `ca/*.p8.enc`. The CLI `--backup` command always produces an ordinary state backup without the optional PKCS#12 artifact.
   * Before restoring, stop CertRobo and any other processes that access its data. Restore the corresponding passphrase and configuration securely, then restore the archive and restart the service. Test recovery on a separate system before relying on the backup.
     ```bash
     sudo systemctl stop certrobo.service
     sudo -u certrobo sh -c 'set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --restore /var/lib/certrobo/backups/certrobo-backup.zip'
     sudo systemctl start certrobo.service
     ```
   * Note that rolling back to an earlier backup after certificates have been delivered to clients cannot undo trust in already-issued certificates; if importing an existing CA identity from AD CS, fence the old signer first, set the initial serial and CRL number floors above the highest previously issued values, and seed any unexpired revoked serials in `/admin`.
   * **CA Key Custody Verification & Mixed-Passphrase Recovery:**
     If a deployment previously encrypted a historical or replacement CA key with a different passphrase (or rotated `/etc/certrobo/ca.pass`), stop the running service, take an offline backup, and converge all stored keys to the configured shared custody secret without overwriting original `.p8.enc` key files. Keep a separate, secure offline copy of all legacy and current passphrases before starting; never use the sole copy of a passphrase as a staging file on the host:
     ```bash
     # 1. Stop the running service and take a consistent offline backup before modifying key custody
     if ! sudo systemctl stop certrobo.service; then
         echo "ERROR: Failed to stop certrobo.service; aborting CA key custody migration." >&2
         false
     elif ! sudo -u certrobo sh -c 'set -e; set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --backup /var/lib/certrobo/backups/pre-reprotect-backup.zip'; then
         echo "ERROR: Pre-migration backup failed; aborting CA key custody migration." >&2
         false
     else
         # 2. Inspect current custody status (a nonzero exit is expected before mixed-passphrase keys are re-protected)
         if ! sudo -u certrobo sh -c 'set -e; set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --verify-ca-custody'; then
             echo "Pre-migration custody mismatch confirmed; proceeding with key re-protection." >&2
         fi

         # 3. Re-protect incompatible keys, verify post-migration custody health, and start the service only if both succeed
         if sudo -u certrobo sh -c 'set -e; set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --reprotect-ca-keys /etc/certrobo/legacy-ca.pass' \
             && sudo -u certrobo sh -c 'set -e; set -a && . /etc/certrobo/certrobo.env && set +a && cd /opt/certrobo && ./CertRobo --verify-ca-custody'; then
             sudo systemctl start certrobo.service
         else
             echo "ERROR: CA key custody migration or post-migration verification failed; keeping certrobo.service stopped." >&2
             false
         fi
     fi
     ```
     Do **not** delete `/etc/certrobo/legacy-ca.pass` or retire your independent offline copy of the legacy passphrase(s) until `--reprotect-ca-keys` and `--verify-ca-custody` have both exited `0`, `certrobo.service` has started cleanly, and active issuance and CRL refresh have been verified. Note that file deletion utilities (such as `rm` or `shred`) do not guarantee physical erasure on SSDs, copy-on-write filesystems, or journaled/networked storage.

5. **Issuer-Specific Publication and Export Behavior**
   * Set `CertRobo__PublicBaseUrl` to the externally reachable plain-HTTP PKI origin. New authorities using default publication paths then receive stable issuer URLs such as `http://pki.contoso.com/authorities/3/issuer.crt` (DER AIA certificate) and `http://pki.contoso.com/authorities/3/ca.crl`. `/ca.crt`, `/ca.p7b`, `/issuer.crt`, `/ca.crl`, and `/ca.crl.pem` remain compatibility aliases for the active issuer; `/rootca.crt` returns only the trust anchor.
   * Historical issuer chains and CRLs remain available by authority ID after rollover. Each issued record retains its actual `CaAuthorityId` and chain, so later downloads do not silently switch to the current issuer.
   * Export ZIPs include leaf PEM, leaf-only PKCS #12 and PKCS #7, full-chain PKCS #12/P7B, a TLS server-chain PEM containing the leaf plus intermediate CA(s), and a separate `rootca.crt` trust anchor. A self-signed root is not inserted into the TLS server-chain file. Leaf `.p12` and `-chained.p12` files inside the export ZIP remain passwordless for convenience and include an empty-password PKCS #12 integrity MAC (`HMAC-SHA1` with `PBES2-PBKDF2-HMAC-SHA256` `AES-256-CBC` bags) to detect accidental container corruption (verified with .NET `X509CertificateLoader` and OpenSSL `3.x`; this MAC does not encrypt or provide confidentiality for the private key because the empty password is public).
   * Certificates issued before issuer-specific URLs were introduced may contain the legacy `/ca.crt` or `/ca.crl` active aliases. Their original issuer records and signed CRLs are preserved, but those already-encoded URLs cannot be changed retrospectively. Pin legacy relying parties to the corresponding `/authorities/{id}/...` resource during rollover.
   * CertRobo publishes CRLs only for certificates it issues under each stored CA identity. It does not mirror a parent CA's CRL/OCSP service and never copies the parent's revocation URL onto leaf certificates.

6. **Disposable AD CS CES Integration Test Procedure**
   * This repository's automated tests validate WSTEP envelopes/parsing and issued, pending, denied, authentication, TLS, transport, ambiguous-submission, restart, retrieval, and manual-fallback states using disposable HTTPS handlers. They do not prove interoperability with a real CES deployment.
   * On an explicitly authorized disposable Windows Server Enterprise CA:
     1. Publish a subordinate-CA template as described above and grant a non-privileged test account Enroll permission.
     2. Install/configure CES with Username/Password authentication and a valid HTTPS Server Authentication certificate.
     3. Trust the HTTPS issuing chain in CertRobo via **Custom Server TLS Trust** if it is private.
     4. Generate a pending Issuing CA request in CertRobo, configure the exact `https://.../service.svc/CES` URL and template name, and submit.
     5. For immediate issuance, expect **Ready for Activation** and verify the displayed fingerprint against `certutil -dump`.
     6. Enable CA manager approval, submit a fresh request, expect **Awaiting Parent CA Approval** with a persisted Request ID, approve it in the CA console, then use **Check Pending Status** and expect **Ready for Activation**.
     7. Deny a fresh request and expect a distinct denied state; use a wrong password and expect authentication failure; present an untrusted or name-mismatched HTTPS certificate and expect TLS/trust failure.
     8. Interrupt the connection after submission and confirm **Submission Outcome Uncertain** blocks ordinary resubmission. Reconcile using the CA Request ID or manual certificate upload.
     9. Before activation, confirm the existing issuer still signs. After explicit activation, issue a test leaf and verify with:
        ```bash
        openssl verify -CAfile parent-root.pem -untrusted certrobo-issuing-ca.pem issued-leaf.crt
        openssl verify -crl_check -CAfile parent-root.pem -untrusted certrobo-issuing-ca.pem -CRLfile certrobo.crl.pem issued-leaf.crt
        ```

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
