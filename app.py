import io
import os
import re
import zipfile
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template, request,
    send_file, session, url_for
)
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from sqlalchemy import (
    CheckConstraint, DateTime, ForeignKey, Index, Integer, LargeBinary,
    String, Text, UniqueConstraint, create_engine, func, or_, select
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
MAX_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"}


def database_url():
    """Render supplies DATABASE_URL. Keep SQLite as a local development fallback."""
    value = os.environ.get("DATABASE_URL", "sqlite:///trustvault_local.db")
    if value.startswith("postgres://"):
        value = value.replace("postgres://", "postgresql+psycopg://", 1)
    elif value.startswith("postgresql://"):
        value = value.replace("postgresql://", "postgresql+psycopg://", 1)
    return value


app = Flask(__name__)
secret_key = os.environ.get("SECRET_KEY")
if os.environ.get("RENDER") and not secret_key:
    raise RuntimeError("SECRET_KEY must be configured in the Render environment.")

app.config.update(
    SECRET_KEY=secret_key or "local-only-change-this-secret",
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("COOKIE_SECURE", "true").lower() == "true"
                           if os.environ.get("RENDER") else
                           os.environ.get("COOKIE_SECURE", "false").lower() == "true"),
    SQLALCHEMY_DATABASE_URI=database_url(),
)
# Render terminates HTTPS at its load balancer and forwards the request internally.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
csrf = CSRFProtect(app)


# -----------------------------------------------------------------------------
# Database models (PostgreSQL in Render; SQLite fallback for local development)
# -----------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


engine_options = {"pool_pre_ping": True}
if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"], **engine_options)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="OWNER", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[str] = mapped_column(String(150), nullable=False)
    file_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class DocumentPermission(Base):
    __tablename__ = "document_permissions"
    __table_args__ = (
        UniqueConstraint("document_id", "user_id", name="uq_document_permission_user"),
        CheckConstraint("permission IN ('READ', 'EDIT')", name="ck_permission_read_edit"),
        Index("ix_permissions_user", "user_id"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    permission: Mapped[str] = mapped_column(String(10), nullable=False)
    granted_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_user", "user_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    document_id: Mapped[int | None] = mapped_column(ForeignKey("documents.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(30), nullable=False)
    details: Mapped[str] = mapped_column(Text, default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


def init_db():
    Base.metadata.create_all(engine)


# Render's start command imports app.py, so create tables at process startup.
init_db()


# -----------------------------------------------------------------------------
# Helpers and authorization
# -----------------------------------------------------------------------------
def get_db():
    return SessionLocal()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "ADMIN":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    return bool(filename and "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS)


def validate_file_content(data: bytes, extension: str) -> bool:
    if not data:
        return False
    if extension == "pdf":
        return data.startswith(b"%PDF-")
    if extension == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if extension in {"jpg", "jpeg"}:
        return data.startswith(b"\xff\xd8\xff")
    if extension == "doc":
        return data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    if extension == "docx":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return "[Content_Types].xml" in archive.namelist() and "word/document.xml" in archive.namelist()
        except zipfile.BadZipFile:
            return False
    if extension == "txt":
        try:
            return b"\x00" not in data and data.decode("utf-8") is not None
        except UnicodeDecodeError:
            return False
    return False


def log_activity(db, user_id, document_id, action, details=""):
    db.add(AuditLog(
        user_id=user_id,
        document_id=document_id,
        action=action,
        details=details,
        ip_address=(request.remote_addr or "")[:64],
    ))


def get_accessible_document(db, document_id, user_id):
    doc = db.get(Document, document_id)
    if not doc:
        return None, None
    if doc.owner_id == user_id:
        return doc, "OWNER"
    permission = db.scalar(select(DocumentPermission.permission).where(
        DocumentPermission.document_id == document_id,
        DocumentPermission.user_id == user_id,
    ))
    if permission in {"READ", "EDIT"}:
        return doc, permission
    return None, None


def save_uploaded_file(uploaded):
    if not uploaded or not uploaded.filename:
        raise ValueError("Choose a file first.")
    if not allowed_file(uploaded.filename):
        raise ValueError("File extension is not allowed.")
    filename = secure_filename(uploaded.filename)
    if not filename or len(filename) > 255:
        raise ValueError("Invalid filename.")
    extension = filename.rsplit(".", 1)[1].lower()
    data = uploaded.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Maximum file size is 10 MB.")
    if not validate_file_content(data, extension):
        raise ValueError("File content does not match the selected file type.")
    return filename, data, uploaded.mimetype or "application/octet-stream"


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    # Health check also verifies database connectivity.
    with get_db() as db:
        db.execute(select(1))
    return {"status": "ok"}, 200


@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or len(name) > 100 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(password) < 10:
            flash("Enter a valid name and email. Password must contain at least 10 characters.", "error")
            return redirect(url_for("register"))
        bootstrap_email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
        bootstrap_password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")
        if bootstrap_email and email == bootstrap_email:
            if not bootstrap_password or password != bootstrap_password:
                flash("This email is reserved for the configured administrator account. Use the bootstrap password set by the project owner.", "error")
                return redirect(url_for("register"))
            role = "ADMIN"
        else:
            role = "OWNER"
        db = get_db()
        try:
            db.add(User(name=name, email=email, password_hash=generate_password_hash(password), role=role))
            db.commit()
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("home"))
        except IntegrityError:
            db.rollback()
            flash("That email address is already registered.", "error")
        finally:
            db.close()
    return render_template("register.html")


@app.post("/login")
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    db = get_db()
    try:
        user = db.scalar(select(User).where(User.email == email))
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session["user_name"] = user.name
            session["role"] = user.role
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))
    finally:
        db.close()
    flash("Invalid email or password.", "error")
    return redirect(url_for("home"))


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.post("/upload")
@login_required
def upload_document():
    try:
        filename, data, content_type = save_uploaded_file(request.files.get("document"))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard"))
    db = get_db()
    try:
        doc = Document(owner_id=session["user_id"], original_filename=filename,
                       file_size=len(data), content_type=content_type, file_data=data)
        db.add(doc)
        db.flush()
        log_activity(db, session["user_id"], doc.id, "UPLOAD", f"Uploaded {filename}")
        db.commit()
        flash("Document uploaded successfully.", "success")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return redirect(url_for("dashboard"))


@app.get("/download/<int:document_id>")
@login_required
def download_document(document_id):
    db = get_db()
    try:
        doc, level = get_accessible_document(db, document_id, session["user_id"])
        if not doc:
            abort(404)
        data = bytes(doc.file_data)
        filename = doc.original_filename
        content_type = doc.content_type
        log_activity(db, session["user_id"], document_id, "DOWNLOAD", f"Downloaded {filename}")
        db.commit()
    finally:
        db.close()
    return send_file(io.BytesIO(data), mimetype=content_type, as_attachment=True, download_name=filename)


@app.post("/share/<int:document_id>")
@login_required
def share_document(document_id):
    email = request.form.get("email", "").strip().lower()
    permission = request.form.get("permission", "").strip().upper()
    if permission not in {"READ", "EDIT"}:
        flash("Choose READ or EDIT permission.", "error")
        return redirect(url_for("dashboard"))
    db = get_db()
    try:
        doc = db.get(Document, document_id)
        if not doc or doc.owner_id != session["user_id"]:
            abort(404)
        recipient = db.scalar(select(User).where(User.email == email))
        if not recipient:
            flash("No account found for that email. The recipient must register first.", "error")
            return redirect(url_for("dashboard"))
        if recipient.id == session["user_id"]:
            flash("You already own this document.", "error")
            return redirect(url_for("dashboard"))
        existing = db.scalar(select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == recipient.id,
        ))
        if existing:
            existing.permission = permission
            existing.granted_by = session["user_id"]
            existing.created_at = datetime.now(timezone.utc)
        else:
            db.add(DocumentPermission(document_id=document_id, user_id=recipient.id,
                                      permission=permission, granted_by=session["user_id"]))
        log_activity(db, session["user_id"], document_id, "SHARE", f"Granted {permission} to {email}")
        db.commit()
        flash(f"{permission} access granted.", "success")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return redirect(url_for("dashboard"))


@app.post("/revoke/<int:document_id>/<int:user_id>")
@login_required
def revoke_access(document_id, user_id):
    db = get_db()
    try:
        doc = db.get(Document, document_id)
        if not doc or doc.owner_id != session["user_id"]:
            abort(404)
        permission = db.scalar(select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_id,
        ))
        if permission:
            db.delete(permission)
            log_activity(db, session["user_id"], document_id, "REVOKE", f"Revoked access for user ID {user_id}")
            db.commit()
            flash("Access revoked.", "success")
        else:
            flash("No matching permission was found.", "warning")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return redirect(url_for("dashboard"))


@app.post("/replace/<int:document_id>")
@login_required
def replace_document(document_id):
    db = get_db()
    try:
        doc, level = get_accessible_document(db, document_id, session["user_id"])
        if not doc or level not in {"OWNER", "EDIT"}:
            abort(404)
        try:
            filename, data, content_type = save_uploaded_file(request.files.get("document"))
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        doc.original_filename = filename
        doc.file_size = len(data)
        doc.content_type = content_type
        doc.file_data = data
        doc.updated_at = datetime.now(timezone.utc)
        log_activity(db, session["user_id"], document_id, "EDIT", f"Replaced document with {filename}")
        db.commit()
        flash("Document replaced successfully.", "success")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return redirect(url_for("dashboard"))


@app.get("/audit")
@login_required
def audit_logs():
    db = get_db()
    try:
        logs = db.scalars(
            select(AuditLog)
            .outerjoin(Document, AuditLog.document_id == Document.id)
            .where(or_(AuditLog.user_id == session["user_id"], Document.owner_id == session["user_id"]))
            .order_by(AuditLog.created_at.desc())
            .limit(500)
        ).all()
        # Resolve related labels without exposing unrelated activity.
        rows = []
        for log in logs:
            user = db.get(User, log.user_id) if log.user_id else None
            doc = db.get(Document, log.document_id) if log.document_id else None
            rows.append({"action": log.action, "details": log.details,
                         "ip_address": log.ip_address, "created_at": log.created_at,
                         "user_name": user.name if user else "Unknown",
                         "original_filename": doc.original_filename if doc else None})
    finally:
        db.close()
    return render_template("audit_logs.html", logs=rows)


@app.get("/dashboard")
@login_required
def dashboard():
    query = request.args.get("q", "").strip()[:100]
    pattern = f"%{query}%"
    db = get_db()
    try:
        documents = db.scalars(select(Document).where(
            Document.owner_id == session["user_id"],
            Document.original_filename.ilike(pattern),
        ).order_by(Document.created_at.desc())).all()
        shared_documents = db.execute(
            select(Document, DocumentPermission.permission, User.name)
            .join(DocumentPermission, DocumentPermission.document_id == Document.id)
            .join(User, User.id == Document.owner_id)
            .where(DocumentPermission.user_id == session["user_id"], Document.original_filename.ilike(pattern))
            .order_by(DocumentPermission.created_at.desc())
        ).all()
        access_rows = db.execute(
            select(DocumentPermission.document_id, DocumentPermission.user_id,
                   User.name, User.email, DocumentPermission.permission)
            .join(User, User.id == DocumentPermission.user_id)
            .join(Document, Document.id == DocumentPermission.document_id)
            .where(Document.owner_id == session["user_id"])
            .order_by(DocumentPermission.created_at.desc())
        ).all()
        access_by_document = {}
        for row in access_rows:
            access_by_document.setdefault(row.document_id, []).append({
                "user_id": row.user_id, "user_name": row.name,
                "email": row.email, "permission": row.permission,
            })
        shared = [{"doc": row[0], "my_permission": row[1], "owner_name": row[2]} for row in shared_documents]
    finally:
        db.close()
    return render_template("dashboard.html", name=session.get("user_name"), role=session.get("role"),
                           documents=documents, shared_documents=shared,
                           access_by_document=access_by_document, search_query=query)


@app.get("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    try:
        users = db.scalars(select(User).order_by(User.created_at.desc())).all()
        documents = db.execute(select(Document, User.name, User.email)
                               .join(User, User.id == Document.owner_id)
                               .order_by(Document.created_at.desc())).all()
        logs = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(100)).all()
    finally:
        db.close()
    return render_template("admin.html", users=users, documents=documents, logs=logs)


@app.errorhandler(413)
def too_large(_error):
    flash("File is too large. Maximum size is 10 MB.", "error")
    return redirect(url_for("dashboard"))


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
