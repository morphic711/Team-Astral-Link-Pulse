import csv
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
import io
import os
import re
import secrets
import string
from urllib.parse import urlsplit
from uuid import UUID as PythonUUID, uuid4

import click # type: ignore
from dotenv import load_dotenv # type: ignore
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from flask_wtf.csrf import CSRFProtect # type: ignore
from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, func, text, update # type: ignore
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID # type: ignore
from sqlalchemy.exc import IntegrityError # type: ignore
from werkzeug.security import check_password_hash, generate_password_hash # type: ignore

# Load the private database URL from the local .env file.
# Prefer this project's local settings over stale DATABASE_URL values inherited
# from a shell. Production environments do not include the ignored local .env.
load_dotenv(override=True)
database_url = os.getenv("DATABASE_URL", "").strip()

if not database_url:
    raise RuntimeError("DATABASE_URL is missing. Copy .env.example to .env and add your Supabase connection string.")

# Tell SQLAlchemy to use the Psycopg 3 database driver.
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)

if not database_url.startswith("postgresql+psycopg://"):
    raise RuntimeError("DATABASE_URL must be a PostgreSQL connection string from Supabase.")

secret_key = os.getenv("SECRET_KEY", "").strip()
if not secret_key:
    raise RuntimeError("SECRET_KEY is missing. Add a private random value to .env before starting Flask.")

# Create the Flask app and connect Flask-SQLAlchemy to Supabase Postgres.
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
db = SQLAlchemy(app)
csrf = CSRFProtect(app)


class User(db.Model):
    """A LinkPulse account with a securely hashed password."""

    __tablename__ = "app_users"
    __table_args__ = (
        CheckConstraint("role IN ('user', 'admin')", name="ck_app_users_role"),
        Index("uq_app_users_email_lower", text("lower(email)"), unique=True),
    )

    id = db.Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4, server_default=text("gen_random_uuid()"))
    email = db.Column(String(320), nullable=False)
    password_hash = db.Column(String(255), nullable=False)
    role = db.Column(String(16), nullable=False, default="user", server_default=text("'user'"))
    created_at = db.Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    links = db.relationship("Link", back_populates="owner")

    def set_password(self, password: str) -> None:
        """Store a one-way password hash instead of the original password."""
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        """Check a submitted password against the saved one-way hash."""
        return check_password_hash(self.password_hash, password)


class Link(db.Model):
    """A short code and the destination it redirects to."""

    __tablename__ = "links"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'disabled')", name="ck_links_status"),
        CheckConstraint("click_count >= 0", name="ck_links_click_count"),
        CheckConstraint("click_limit IS NULL OR click_limit > 0", name="ck_links_click_limit"),
        CheckConstraint("short_code ~ '^[A-Za-z0-9_-]{1,32}$'", name="ck_links_short_code_format"),
        CheckConstraint("length(btrim(destination_url)) > 0", name="ck_links_destination_not_empty"),
        Index("ix_links_user_id", "user_id"),
    )

    id = db.Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4, server_default=text("gen_random_uuid()"))
    user_id = db.Column(PostgresUUID(as_uuid=True), ForeignKey("app_users.id"), nullable=False)
    short_code = db.Column(String(32), nullable=False, unique=True)
    destination_url = db.Column(Text, nullable=False)
    status = db.Column(String(16), nullable=False, default="active", server_default=text("'active'"))
    expires_at = db.Column(DateTime(timezone=True))
    click_limit = db.Column(Integer)
    click_count = db.Column(Integer, nullable=False, default=0, server_default=text("0"))
    password_hash = db.Column(String(255))
    disabled_reason = db.Column(Text)
    created_at = db.Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    owner = db.relationship("User", back_populates="links")
    click_events = db.relationship("ClickEvent", back_populates="link")


class ClickEvent(db.Model):
    """One visit to a short link, with only a hashed IP address stored."""

    __tablename__ = "click_events"
    __table_args__ = (
        CheckConstraint("source IN ('direct', 'qr')", name="ck_click_events_source"),
        Index("ix_click_events_link_clicked_at", "link_id", "clicked_at"),
    )

    id = db.Column(BigInteger, primary_key=True, autoincrement=True)
    link_id = db.Column(PostgresUUID(as_uuid=True), ForeignKey("links.id"), nullable=False)
    clicked_at = db.Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    referrer = db.Column(Text)
    device_type = db.Column(String(80))
    browser = db.Column(String(120))
    os = db.Column(String(120))
    country = db.Column(String(2))
    ip_hash = db.Column(String(64))
    source = db.Column(String(16), nullable=False, default="direct", server_default=text("'direct'"))
    is_bot = db.Column(Boolean, nullable=False, default=False, server_default=text("false"))

    link = db.relationship("Link", back_populates="click_events")


def get_logged_in_user():
    """Load the signed-in account from the session cookie, if it still exists."""
    user_id = session.get("user_id")
    if not user_id:
        return None

    try:
        user = db.session.get(User, PythonUUID(user_id))
    except ValueError:
        session.clear()
        return None

    if user is None:
        session.clear()
    return user


def generate_short_code() -> str:
    """Choose an unused, seven-character Base62 code."""
    alphabet = string.ascii_letters + string.digits
    for _ in range(5):
        code = "".join(secrets.choice(alphabet) for _ in range(7))
        if not db.session.query(Link.id).filter_by(short_code=code).first():
            return code
    raise RuntimeError("Could not find an unused short code.")


def visit_details() -> dict:
    """Keep simple browser/device labels and an HMAC of the visitor IP."""
    agent = request.user_agent.string.lower()
    if any(token in agent for token in ("ipad", "tablet", "kindle")):
        device = "Tablet"
    elif any(token in agent for token in ("mobile", "iphone", "android")):
        device = "Mobile"
    elif agent:
        device = "Desktop"
    else:
        device = None

    if "edg/" in agent:
        browser = "Edge"
    elif "opr/" in agent or "opera" in agent:
        browser = "Opera"
    elif "firefox/" in agent or "fxios/" in agent:
        browser = "Firefox"
    elif "chrome/" in agent or "crios/" in agent:
        browser = "Chrome"
    elif "safari/" in agent:
        browser = "Safari"
    else:
        browser = None

    if "windows" in agent:
        operating_system = "Windows"
    elif "iphone" in agent or "ipad" in agent or "ios" in agent:
        operating_system = "iOS"
    elif "android" in agent:
        operating_system = "Android"
    elif "mac os" in agent or "macintosh" in agent:
        operating_system = "macOS"
    elif "linux" in agent:
        operating_system = "Linux"
    else:
        operating_system = None

    ip_address = request.remote_addr
    ip_hash = None
    if ip_address:
        ip_hash = hmac.new(
            app.config["SECRET_KEY"].encode("utf-8"),
            ip_address.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    bot = any(token in agent for token in ("bot", "crawler", "spider", "headless", "preview"))
    return {
        "referrer": request.referrer,
        "device_type": device,
        "browser": browser,
        "os": operating_system,
        "ip_hash": ip_hash,
        "is_bot": bot,
    }


@app.get("/")
def home():
    if get_logged_in_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("register"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Create a regular user account; admin access is never chosen on signup."""
    if get_logged_in_user():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password_confirmation = request.form.get("password_confirmation", "")

        if len(email) > 320 or "@" not in email or email.startswith("@") or email.endswith("@") or " " in email:
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Use a password with at least 8 characters.", "error")
        elif len(password) > 128:
            flash("Use a password with 128 characters or fewer.", "error")
        elif password != password_confirmation:
            flash("Those passwords do not match. Try again.", "error")
        elif db.session.query(User.id).filter(func.lower(User.email) == email).first():
            flash("An account with that email already exists. Try signing in.", "error")
        else:
            user = User(email=email, role="user")
            user.set_password(password)
            db.session.add(user)

            try:
                db.session.commit()
            except IntegrityError:
                # The unique database index also handles two signups arriving together.
                db.session.rollback()
                flash("An account with that email already exists. Try signing in.", "error")
            else:
                session.clear()
                session["user_id"] = str(user.id)
                flash("Your LinkPulse account is ready.", "success")
                return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Sign in without revealing whether an email address has an account."""
    if get_logged_in_user():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter(func.lower(User.email) == email).first()

        if user is None or not user.check_password(password):
            flash("That email and password combination was not recognized.", "error")
        else:
            session.clear()
            session["user_id"] = str(user.id)
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.post("/logout")
def logout():
    """Sign out; this is a POST form so CSRF protection applies."""
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.get("/dashboard")
def dashboard():
    """Show the signed-in user's own short links."""
    user = get_logged_in_user()
    if user is None:
        flash("Sign in to open your workspace.", "error")
        return redirect(url_for("login"))

    links_query = Link.query if user.role == "admin" else Link.query.filter_by(user_id=user.id)
    links = links_query.order_by(Link.created_at.desc()).all()
    sample_codes = {"demo-event", "demo-launch", "demo-signup"}
    return render_template(
        "dashboard.html", user=user, links=links, sample_codes=sample_codes,
        today_utc=datetime.now(timezone.utc).date().isoformat(),
        now_utc=datetime.now(timezone.utc),
    )


@app.post("/links")
def create_link():
    """Save a short link for the current account."""
    user = get_logged_in_user()
    if user is None:
        flash("Sign in before creating a link.", "error")
        return redirect(url_for("login"))

    destination = request.form.get("destination_url", "").strip()
    requested_code = request.form.get("short_code", "").strip()
    expiry_date = request.form.get("expires_at", "").strip()
    click_limit_value = request.form.get("click_limit", "").strip()
    link_password = request.form.get("link_password", "")

    expires_at = None
    if expiry_date:
        try:
            # The date control is interpreted as the end of that date in UTC.
            expires_at = datetime.strptime(expiry_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        except ValueError:
            flash("Choose a valid expiry date.", "error")
            return redirect(url_for("dashboard"))

    click_limit = None
    if click_limit_value:
        try:
            click_limit = int(click_limit_value)
        except ValueError:
            flash("Click limit must be a positive whole number.", "error")
            return redirect(url_for("dashboard"))
        if click_limit < 1:
            flash("Click limit must be a positive whole number.", "error")
            return redirect(url_for("dashboard"))
    if len(link_password) > 128:
        flash("Link passwords must be 128 characters or fewer.", "error")
        return redirect(url_for("dashboard"))

    if not destination or len(destination) > 2048:
        flash("Enter a destination URL up to 2,048 characters long.", "error")
        return redirect(url_for("dashboard"))

    try:
        parsed_url = urlsplit(destination)
        hostname = parsed_url.hostname
        parsed_url.port  # Accessing this also rejects invalid port numbers.
    except ValueError:
        flash("Use a valid web address that starts with http:// or https://.", "error")
        return redirect(url_for("dashboard"))

    if (
        parsed_url.scheme.lower() not in {"http", "https"}
        or not hostname
        or any(character.isspace() for character in destination)
        or parsed_url.username is not None
        or parsed_url.password is not None
    ):
        flash("Use a valid web address that starts with http:// or https://.", "error")
        return redirect(url_for("dashboard"))

    reserved_codes = {"admin", "api", "dashboard", "health", "login", "logout", "register", "static"}
    if requested_code and not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", requested_code):
        flash("Custom codes can use 1–32 letters, numbers, hyphens, or underscores.", "error")
        return redirect(url_for("dashboard"))
    if requested_code.lower() in reserved_codes:
        flash("That custom code is reserved. Choose another one.", "error")
        return redirect(url_for("dashboard"))

    code = requested_code or generate_short_code()
    if db.session.query(Link.id).filter_by(short_code=code).first():
        flash("That short code is already in use. Choose another one.", "error")
        return redirect(url_for("dashboard"))

    link = Link(
        user_id=user.id,
        short_code=code,
        destination_url=destination,
        expires_at=expires_at,
        click_limit=click_limit,
        password_hash=generate_password_hash(link_password, method="scrypt") if link_password else None,
    )
    db.session.add(link)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("That short code was just claimed. Choose another one and try again.", "error")
    else:
        flash("Your short link has been created.", "success")

    return redirect(url_for("dashboard"))


@app.post("/links/import")
def import_links():
    """Import valid destination_url,short_code rows from a CSV file."""
    user = get_logged_in_user()
    if user is None:
        flash("Sign in before importing links.", "error")
        return redirect(url_for("login"))

    upload = request.files.get("csv_file")
    if upload is None or not upload.filename:
        flash("Choose a CSV file to import.", "error")
        return redirect(url_for("dashboard"))
    contents = upload.read(2_000_001)
    if len(contents) > 2_000_000:
        flash("CSV files must be 2 MB or smaller.", "error")
        return redirect(url_for("dashboard"))
    try:
        text_content = contents.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text_content, newline=""))
    except (UnicodeDecodeError, csv.Error):
        flash("Could not read that file. Save it as a UTF-8 CSV and try again.", "error")
        return redirect(url_for("dashboard"))

    headers = {header.strip().lower() for header in (reader.fieldnames or []) if header}
    if "destination_url" not in headers:
        flash("CSV needs a destination_url column. short_code is optional.", "error")
        return redirect(url_for("dashboard"))

    reserved_codes = {"admin", "api", "dashboard", "health", "login", "logout", "register", "static"}
    imported = 0
    errors = []
    for row_number, row in enumerate(reader, start=2):
        if row_number > 501:
            errors.append("Only the first 500 data rows were processed.")
            break
        normalized = {(key or "").strip().lower(): (value or "").strip() for key, value in row.items() if key}
        destination = normalized.get("destination_url", "")
        requested_code = normalized.get("short_code", "")
        try:
            parsed_url = urlsplit(destination)
            hostname = parsed_url.hostname
            parsed_url.port
            valid_url = (
                bool(destination) and len(destination) <= 2048
                and parsed_url.scheme.lower() in {"http", "https"} and bool(hostname)
                and not any(character.isspace() for character in destination)
                and parsed_url.username is None and parsed_url.password is None
            )
        except ValueError:
            valid_url = False
        if not valid_url:
            errors.append(f"Row {row_number}: invalid destination_url.")
            continue
        if requested_code and (
            not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", requested_code)
            or requested_code.lower() in reserved_codes
        ):
            errors.append(f"Row {row_number}: invalid or reserved short_code.")
            continue
        code = requested_code or generate_short_code()
        if db.session.query(Link.id).filter_by(short_code=code).first():
            errors.append(f"Row {row_number}: short_code '{code}' is already in use.")
            continue
        db.session.add(Link(user_id=user.id, short_code=code, destination_url=destination))
        try:
            db.session.commit()
            imported += 1
        except IntegrityError:
            db.session.rollback()
            errors.append(f"Row {row_number}: short_code '{code}' is already in use.")

    if errors:
        detail = " ".join(errors[:8])
        if len(errors) > 8:
            detail += f" Plus {len(errors) - 8} more row issue(s)."
        flash(f"Imported {imported} link(s). {detail}", "error" if not imported else "success")
    else:
        flash(f"Imported {imported} link(s).", "success")
    return redirect(url_for("dashboard"))


@app.post("/admin/links/<link_id>/disable")
def disable_link(link_id: str):
    """Let platform admins stop a link while keeping its history intact."""
    user = get_logged_in_user()
    if user is None:
        flash("Sign in before managing links.", "error")
        return redirect(url_for("login"))
    if user.role != "admin":
        abort(403)

    try:
        link_uuid = PythonUUID(link_id)
    except ValueError:
        abort(404)

    link = db.session.get(Link, link_uuid)
    if link is None:
        abort(404)
    if link.status == "disabled":
        flash("That link is already disabled.", "error")
        return redirect(url_for("dashboard"))

    link.status = "disabled"
    link.disabled_reason = "Disabled by an administrator"
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Could not disable link %s.", link_id)
        flash("The link could not be disabled. Please try again.", "error")
    else:
        flash("Link disabled. Its analytics remain available.", "success")

    return redirect(url_for("dashboard"))


@app.post("/links/bulk")
def bulk_manage_links():
    """Apply a requested management action to selected links the user may manage."""
    user = get_logged_in_user()
    if user is None:
        flash("Sign in before managing links.", "error")
        return redirect(url_for("login"))

    action = request.form.get("action", "")
    if action not in {"disable", "enable", "delete"}:
        flash("Choose a bulk action first.", "error")
        return redirect(url_for("dashboard"))

    raw_link_ids = request.form.getlist("link_ids")
    try:
        link_ids = {PythonUUID(link_id) for link_id in raw_link_ids}
    except ValueError:
        abort(400)
    if not link_ids:
        flash("Select at least one link.", "error")
        return redirect(url_for("dashboard"))

    links_query = Link.query.filter(Link.id.in_(link_ids))
    if user.role != "admin":
        links_query = links_query.filter_by(user_id=user.id)
    links = links_query.all()
    if len(links) != len(link_ids):
        abort(403)

    try:
        if action == "delete":
            ClickEvent.query.filter(ClickEvent.link_id.in_(link_ids)).delete(synchronize_session=False)
            Link.query.filter(Link.id.in_(link_ids)).delete(synchronize_session=False)
            success_message = f"Deleted {len(links)} link(s) and their analytics."
        elif action == "disable":
            changed = 0
            for link in links:
                if link.status != "disabled":
                    link.status = "disabled"
                    link.disabled_reason = (
                        "Disabled in bulk by an administrator"
                        if user.role == "admin" else "Disabled in bulk by the link owner"
                    )
                    changed += 1
            success_message = f"Disabled {changed} link(s). Their analytics remain available."
        else:
            for link in links:
                link.status = "active"
                link.disabled_reason = None
            success_message = f"Enabled {len(links)} link(s)."
        db.session.commit()
        flash(success_message, "success")
    except Exception:
        db.session.rollback()
        app.logger.exception("Could not apply bulk action %s to selected links.", action)
        flash("The selected links could not be updated. Please try again.", "error")

    return redirect(url_for("dashboard"))


@app.route("/<short_code>", methods=["GET", "POST"])
def redirect_short_link(short_code: str):
    """Enforce link rules before recording a visit and redirecting."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", short_code):
        return render_template("link_error.html", message="That short link was not found."), 404

    link = Link.query.filter_by(short_code=short_code).first()
    if link is None:
        return render_template("link_error.html", message="That short link was not found."), 404
    if link.status != "active":
        return render_template("link_error.html", message="This short link was disabled by an administrator."), 410

    if link.expires_at is not None:
        expiry = link.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expiry:
            return render_template("link_error.html", message="This short link has expired."), 410

    if link.click_limit is not None and link.click_count >= link.click_limit:
        return render_template("link_error.html", message="This short link has reached its click limit."), 410

    if link.password_hash:
        if request.method == "POST":
            submitted_password = request.form.get("password", "")
            if not check_password_hash(link.password_hash, submitted_password):
                return render_template(
                    "link_password.html", short_code=link.short_code,
                    error="That password did not match. Try again.",
                ), 401
        else:
            return render_template("link_password.html", short_code=link.short_code, error=None)

    destination_url = link.destination_url
    details = visit_details()
    event = ClickEvent(link_id=link.id, source="direct", **details)
    db.session.add(event)
    # Update the counter in SQL so simultaneous visits each increment it once.
    db.session.execute(
        update(Link).where(Link.id == link.id).values(click_count=Link.click_count + 1)
    )
    try:
        db.session.commit()
    except Exception:
        # A visit should still reach its destination if analytics storage is unavailable.
        db.session.rollback()
        app.logger.exception("Could not record a click for short code %s.", short_code)

    return redirect(destination_url, code=302)


@app.get("/links/<link_id>/analytics")
def link_analytics(link_id: str):
    """Show click data only to the link owner or a platform admin."""
    user = get_logged_in_user()
    if user is None:
        flash("Sign in to view link analytics.", "error")
        return redirect(url_for("login"))

    try:
        link_uuid = PythonUUID(link_id)
    except ValueError:
        return render_template("link_error.html", message="That link report was not found."), 404

    link_query = Link.query.filter_by(id=link_uuid)
    if user.role != "admin":
        link_query = link_query.filter_by(user_id=user.id)
    link = link_query.first()
    if link is None:
        return render_template("link_error.html", message="That link report was not found."), 404

    recent_clicks = (
        ClickEvent.query.filter_by(link_id=link.id)
        .order_by(ClickEvent.clicked_at.desc())
        .limit(20)
        .all()
    )
    return render_template("analytics.html", link=link, recent_clicks=recent_clicks, user=user)


@app.cli.command("seed-admin")
@click.option("--email", prompt="Admin email")
def seed_admin(email: str) -> None:
    """Create an admin account or explicitly promote an existing account."""
    email = email.strip().lower()
    if len(email) > 320 or "@" not in email or email.startswith("@") or email.endswith("@") or " " in email:
        raise click.ClickException("Enter a valid email address.")

    user = User.query.filter(func.lower(User.email) == email).first()
    if user is not None:
        if user.role == "admin":
            click.echo("That account is already an admin; no changes were made.")
            return
        if not click.confirm(f"Promote {email} from user to admin?", default=False):
            click.echo("No changes were made.")
            return

        user.role = "admin"
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise click.ClickException("Could not update the account role. No changes were saved.")
        click.echo(f"Promoted {email} to admin. Their password is unchanged.")
        return

    password = click.prompt("Admin password", hide_input=True, confirmation_prompt=True)
    if len(password) < 12 or len(password) > 128:
        raise click.ClickException("Use an admin password between 12 and 128 characters.")

    admin = User(email=email, role="admin")
    admin.set_password(password)
    db.session.add(admin)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise click.ClickException("An account with that email was just created. Run the command again to review it.")
    click.echo(f"Created admin account for {email}. Sign in at /login.")


@app.cli.command("seed-demo")
@click.option("--email", prompt="Email of the account that will own the sample links")
def seed_demo(email: str) -> None:
    """Add clearly named sample links and click events to an existing account."""
    email = email.strip().lower()
    user = User.query.filter(func.lower(User.email) == email).first()
    if user is None:
        raise click.ClickException("That account was not found. Create an account first, then run this command.")

    samples = [
        ("demo-event", "https://example.com/event", 5),
        ("demo-launch", "https://example.com/product-launch", 8),
        ("demo-signup", "https://example.com/newsletter", 3),
    ]
    existing = [code for code, _, _ in samples if Link.query.filter_by(short_code=code).first()]
    if existing:
        raise click.ClickException(
            "Sample codes already exist: " + ", ".join(existing) + ". No sample data was added."
        )

    now = datetime.now(timezone.utc)
    try:
        for code, destination, visit_count in samples:
            link = Link(
                user_id=user.id,
                short_code=code,
                destination_url=destination,
                click_count=visit_count,
            )
            db.session.add(link)
            db.session.flush()
            for visit_number in range(visit_count):
                db.session.add(ClickEvent(
                    link_id=link.id,
                    clicked_at=now - timedelta(days=(visit_number % 7), hours=visit_number * 2),
                    referrer="https://example.com/",
                    device_type="Desktop" if visit_number % 2 == 0 else "Mobile",
                    browser="Chrome" if visit_number % 2 == 0 else "Safari",
                    os="Windows" if visit_number % 2 == 0 else "iOS",
                    ip_hash=hashlib.sha256(f"linkpulse-demo-{code}-{visit_number}".encode()).hexdigest(),
                    source="direct",
                    is_bot=False,
                ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise click.ClickException("Could not save the sample data; the database changes were rolled back.")

    click.echo(f"Added 3 sample links and {sum(count for _, _, count in samples)} sample visits for {email}.")


# Check the database connection without creating or changing any tables.
@app.get("/health/database")
def database_health():
    try:
        with db.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        app.logger.exception("Supabase database connection failed.")
        return {"database": "connection_failed"}, 503

    return {"database": "connected"}


# Start Flask's local development server when this file is run directly.
if __name__ == "__main__":
    app.run(debug=True)
