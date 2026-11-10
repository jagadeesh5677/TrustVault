# TrustVault Threat Notes

## Assets
- User credentials and sessions
- Uploaded document contents and metadata
- Sharing permissions and audit history
- PostgreSQL connection credentials and Flask secret key

## Main threats and mitigations
- **Unauthorized document access:** Every download and replacement checks ownership or explicit READ/EDIT permission on the server.
- **CSRF:** State-changing forms use Flask-WTF CSRF protection.
- **Password disclosure:** Passwords are stored as Werkzeug password hashes, not plaintext.
- **Unsafe filenames/path traversal:** Uploaded names are normalized with `secure_filename`; stored bytes are held in PostgreSQL, not served from a user-controlled path.
- **Oversized or mislabeled uploads:** Request size is limited to 10 MB and basic file signatures are checked. This is not malware scanning.
- **Secret leakage:** Secrets are environment variables and `.env` is ignored by Git.
- **Audit privacy:** Users can see their own actions and activity on documents they own; admin view is role-restricted.

## Known limitations
- No antivirus/malware scanning, account verification, password reset, or rate limiting.
- Signature checks are basic and can be bypassed by crafted files.
- Storing file bytes in PostgreSQL is appropriate only for a small demo; use private object storage for larger workloads.
- Free Render Postgres expires after 30 days. Use paid storage and backups for long-lived data.
- The app has not undergone an independent penetration test.
