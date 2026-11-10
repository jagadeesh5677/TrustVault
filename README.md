# TrustVault — Render + PostgreSQL deployment

TrustVault is a Flask application for private document upload, sharing, permissions, and audit history. This version is configured for Render Web Services and Render PostgreSQL.

## Architecture

- **Frontend:** Flask/Jinja templates and CSS served by the same web service.
- **Backend:** Flask + Gunicorn.
- **Database:** Render PostgreSQL using SQLAlchemy and psycopg 3.
- **File storage:** Document bytes are stored in PostgreSQL (`BYTEA`) in this demo deployment. This avoids losing uploaded files when Render replaces the web service filesystem.

### File-storage trade-off

The app limits each file to 10 MB and stores the file bytes in PostgreSQL. This is convenient for a small hiring challenge/demo, but it is not the ideal storage architecture for a high-volume production vault. For production scale, move file bytes to private S3-compatible object storage and keep only object keys/metadata in PostgreSQL.

## Deploy using GitHub + Render Blueprint

1. Extract this project folder.
2. Create a new GitHub repository, for example `trustvault`.
3. Copy the contents of this folder into the repository root. Ensure `app.py`, `render.yaml`, and `requirements.txt` are at the root, not one folder deeper.
4. Commit and push the files to GitHub.
5. Sign in to Render and choose **New → Blueprint**.
6. Connect the GitHub repository containing `render.yaml`.
7. Review the resources and click **Apply**. Render creates the PostgreSQL database and web service.
8. When asked for `BOOTSTRAP_ADMIN_EMAIL`, enter the email address you intend to use for your administrator account. This is not a password.
9. Wait for the deployment to finish. Open the web service's `onrender.com` URL.
10. Register using the exact email entered for `BOOTSTRAP_ADMIN_EMAIL`. That first matching account is assigned the `ADMIN` role. Register other accounts normally.
11. Test upload, download, sharing, READ, EDIT replacement, revocation, audit logs, and logout.

## Render service settings (if creating manually)

- Runtime: Python 3
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --workers 2 --threads 4 --timeout 120`
- Health check path: `/healthz`
- Environment variables:
  - `DATABASE_URL`: Render Postgres **Internal Database URL** (same region as web service)
  - `SECRET_KEY`: long random secret (Render can generate one)
  - `COOKIE_SECURE`: `true`
  - `BOOTSTRAP_ADMIN_EMAIL`: reserved administrator email address
  - `BOOTSTRAP_ADMIN_PASSWORD`: one-time bootstrap password for creating that administrator account

Do not put database passwords or `SECRET_KEY` in GitHub. Configure them only in Render's Environment settings.

## Local development (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

The local fallback database is `trustvault_local.db`. Set a local `DATABASE_URL` if you want to test against PostgreSQL. Do not use the production database for local experiments.

## Features

- Registration, login, logout, password hashing, CSRF protection
- PostgreSQL-backed users, documents, permissions, and audit logs
- Upload/download with per-document authorization
- READ and EDIT access; EDIT users may replace shared document contents
- Owner-only sharing and revocation
- Filename search for owned and shared documents
- Audit history scoped to the current user's activity and documents they own
- Admin overview
- Basic file signature/content checks and 10 MB limit
- Health check endpoint and security response headers

## Admin bootstrap

Set `BOOTSTRAP_ADMIN_EMAIL` in Render before creating the administrator account. Register using that same email. Do not leave this variable set to a shared or publicly known address. Once the admin account is created, you can remove the variable from Render if you do not need to bootstrap another admin. Existing user roles are not automatically changed on later deploys.

## Important Render plan limitations

The included `render.yaml` uses free plans for a low-cost demonstration. Render's free web services can spin down after inactivity, and free Render Postgres databases expire after 30 days. A free web service also has an ephemeral filesystem; this app deliberately stores file bytes in PostgreSQL rather than local disk. Before presenting this as a long-lived company service, upgrade to a paid Postgres plan and an appropriate paid web-service plan, and arrange backups.

## Data migration

This project creates a new PostgreSQL schema. It does **not** automatically copy the old SQLite database or the old `uploads/` directory from your Windows project. If you need to preserve existing local accounts and documents, perform a separate controlled migration; do not upload your SQLite database or document files to a public GitHub repository.

## Security limitations

This is a hiring-challenge/demo baseline, not a fully audited high-assurance document vault. Before real sensitive business use, add malware scanning, email verification, password reset, rate limiting, stronger content inspection, object-storage encryption/key management, operational monitoring, formal database migrations, and an independent security review. Do not upload confidential company documents to a demo instance without approval.
