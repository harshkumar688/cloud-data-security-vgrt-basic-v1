# Cloud Data Security Enhancement System Using V-GRT Methodology

Basic V1 prototype implementing account registration/login, per-account file isolation, encrypted upload/download, and security audit events.

## What is implemented

- Java 25, Spring Boot 4.1.2, Spring MVC, Spring Security, Spring Data JPA, Thymeleaf, Maven.
- Public account registration; passwords are stored as BCrypt hashes. Registration requires a 12–72 character password.
- Each account sees and downloads only its own files. File downloads use an owner-scoped database query; an unknown or foreign file ID returns 404 and creates a denial audit event.
- Uploads up to 10 MB are encrypted in the backend with a fresh AES-256-GCM key and nonce. The file key is wrapped with RSA-OAEP using SHA-256/MGF1-SHA-256. A SHA-256 digest of the original bytes is verified on download.
- Only ciphertext is written under the protected object directory. The database stores metadata, nonce, digest and RSA-wrapped AES key, not plaintext file bytes.
- Audit events cover registration, successful and failed login, upload, download and denied file access. Events contain no password or key material.
- CSRF protection remains enabled for browser forms. A limited audit view is available to users whose `role` is `ADMIN`.

V-GRT in this prototype means **Virtualization** through logical per-account isolation, **Governance** through account-scoped ownership and administrator audit access, and **Trustworthy Security** through encryption and integrity verification. Rule-based risk assessment, recommendations, file sharing/permission grants, tenant workspaces, data classification, retention rules, and evaluation-run comparisons are not implemented in this basic V1.

## Platform Pages & Routes

- `/` — Premium Overview Home (Problem statement, V-GRT methodology preview, data flow overview, CTA)
- `/dashboard` — Enterprise Security Dashboard (User account status, file metrics, 7-day activity trend chart, payload composition, risk assessment summary, recent audit timeline, quick upload/download shortcuts)
- `/vault` — Personal Encrypted Vault (Multi-tenant file list, per-object encryption status, direct download with SHA-256 integrity check)
- `/about` — About the Project (Problem statement, importance of cloud security, project objectives, proposed solution, scope and limitations matrix)
- `/methodology` — V-GRT Methodology (In-depth analysis of Virtualization, Governance, Risk Assessment, and Trustworthy Cryptography)
- `/architecture` — System Architecture (Interactive 10-stage end-to-end pipeline diagram, component connectivity breakdown, technical implementation matrix)
- `/admin/audit` — Forensic Audit Ledger (Chronological audit history with outcome status and timestamps for compliance auditing)


## Run locally

- JDK 25.
- Network access the first time Maven Wrapper downloads Maven and Maven resolves dependencies.

On Windows, run `run-local.cmd` from this project directory. It builds the app, generates an RSA key pair for that process, and starts the server at `http://localhost:8080`. The default database is in-memory H2, so accounts and file metadata are cleared when the app stops. This is for local evaluation only; do not use it for important data.

To view the app from another device on the same trusted Wi-Fi, open this project folder in VS Code, press `Ctrl+Shift+P`, run **Tasks: Run Task**, and choose **Run V-GRT on local network**. The VS Code terminal shows startup output and network instructions. On the other device, open `http://<this-PC-IPv4-address>:8080`; find the address with `ipconfig` on the PC. If prompted, allow Java through Windows Firewall for private networks. This is LAN-only demo access, not public internet hosting. Stop the task with `Ctrl+C`.

The included `mvnw.cmd` bootstraps Maven 3.9.11 in the user's Maven wrapper cache if `mvn` is not installed.

## Vercel preview deployment

Vercel's Container Runtime can build the root `Dockerfile` and run this Spring Boot HTTP app. Import this repository in Vercel after pushing the deployment files to GitHub, keep the project root at the repository root, and use the Container framework preset if Vercel does not select it automatically. The image listens on Vercel's `PORT` and binds to all container interfaces.

Without database or crypto environment variables, the container generates temporary RSA keys and uses the default in-memory H2 database plus `/tmp` file storage. This is only suitable for a disposable preview: Vercel may start multiple instances or scale them down, and accounts, audit records, keys, and uploaded files are not durable. For a persistent deployment, configure an external MySQL database and persistent object storage, provide stable `VGRT_RSA_PUBLIC_KEY` and `VGRT_RSA_PRIVATE_KEY` values as Vercel secrets, and add an object-storage adapter; the current file service writes to the local filesystem and does not yet support remote object storage.

## MySQL setup (optional)

For persistent MySQL storage, use MySQL 8 Community Edition and configure the database and least-privilege account below. Set `DB_URL`, `DB_USERNAME`, and `DB_PASSWORD` before starting the application. Also set a persistent RSA key pair as `VGRT_RSA_PUBLIC_KEY` and `VGRT_RSA_PRIVATE_KEY`; the local launcher deliberately generates a new pair each time and should not be used with persistent data.

### Create the MySQL database

In MySQL, create an application database and least-privilege account (change the password):

```sql
CREATE DATABASE vgrt_securecloud CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'vgrt_app'@'localhost' IDENTIFIED BY 'replace-with-a-long-password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON vgrt_securecloud.* TO 'vgrt_app'@'localhost';
```

Set `DB_URL` to `jdbc:mysql://localhost:3306/vgrt_securecloud?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC`, `DB_USERNAME` to `vgrt_app`, and `DB_PASSWORD` to the password you chose. Hibernate `ddl-auto=update` is enabled for this prototype; use reviewed migrations before production use.

## Generate RSA keys (PowerShell)

From this project directory:

```powershell
.\mvnw.cmd package
$keyLines = java -jar .\target\secure-cloud-0.1.0.jar --generate-crypto-keys
$env:VGRT_RSA_PUBLIC_KEY = (($keyLines | Select-String '^VGRT_RSA_PUBLIC_KEY=').Line -split '=', 2)[1]
$env:VGRT_RSA_PRIVATE_KEY = (($keyLines | Select-String '^VGRT_RSA_PRIVATE_KEY=').Line -split '=', 2)[1]
$env:DB_PASSWORD = 'replace-with-a-long-password'
.\mvnw.cmd spring-boot:run
```

The generated private key is printed once so you can set it in the current shell. Keep it secret, do not paste it into source control or chat, and back it up securely: losing it makes stored files undecryptable. A newly generated RSA key pair cannot decrypt files encrypted with a previous pair. Use a persistent secret manager/keystore and key rotation plan for any deployment beyond a disposable demo.

For manual startup, run `mvnw.cmd spring-boot:run` after setting those environment variables. The default encrypted storage directory is `./data/objects`; it can be changed with `VGRT_STORAGE_ROOT`.

## Administrator audit view

New accounts have the `USER` role. To grant audit-view access, sign in to MySQL as a database administrator and promote a specific account:

```sql
UPDATE app_users SET role = 'ADMIN' WHERE username = 'your-account';
```

Sign out and back in, then use the Audit link. Do not expose the database account or grant route to ordinary users.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DB_URL` | `jdbc:mysql://localhost:3306/vgrt_securecloud?...` | MySQL JDBC URL |
| `DB_USERNAME` | `vgrt_app` | MySQL application user |
| `DB_PASSWORD` | `change-me` | MySQL application password |
| `VGRT_STORAGE_ROOT` | `./data/objects` | Directory containing encrypted object bytes |
| `VGRT_RSA_PUBLIC_KEY` | unset | Base64-encoded X.509 RSA public key |
| `VGRT_RSA_PRIVATE_KEY` | unset | Base64-encoded PKCS#8 RSA private key |
| `PORT` | `8080` | HTTP port |

## Security scope and limitations

This is an educational, single-process prototype. The private RSA key is supplied as an environment variable; environment variables are a demo provisioning mechanism, not a full key-management service. The prototype has no rate limiting/account lockout, email verification, password reset, multi-user tenant workspaces, file sharing, configurable risk rules, recommendations, retention/deletion policy, or comparative evaluation dashboard. `ddl-auto=update` is for local development only. Serve behind HTTPS for any network use. An administrator may read audit events, but does not receive access to user file downloads.

No source from the legacy JSP project was copied into this implementation. Its hardcoded credentials, SQL concatenation, and legacy crypto were excluded.
