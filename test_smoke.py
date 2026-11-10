import os
import tempfile

# Set a throwaway SQLite database before importing the app.
_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.close(_fd)
os.environ["DATABASE_URL"] = "sqlite:///" + _db_path.replace("\\", "/")
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"

import app as trustvault


def test_required_routes_exist():
    endpoints = {rule.endpoint for rule in trustvault.app.url_map.iter_rules()}
    assert {"dashboard", "audit_logs", "replace_document", "admin_dashboard", "healthz"} <= endpoints


def test_healthcheck():
    client = trustvault.app.test_client()
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json["status"] == "ok"
