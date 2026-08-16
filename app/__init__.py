import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO

db           = SQLAlchemy()
login_manager = LoginManager()
bcrypt       = Bcrypt()
socketio     = SocketIO()


def create_app():
    app = Flask(__name__)

    # ── Config ────────────────────────────────────────────────────────
    app.config["SECRET_KEY"]          = os.getenv("SECRET_KEY", "atsm-secret-change-this")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///atsm.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["UPLOAD_FOLDER"]       = os.path.join(os.getcwd(), "scans")

    # ── Init extensions ───────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")

    login_manager.login_view        = "auth.login"
    login_manager.login_message     = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    # ── Register blueprints ───────────────────────────────────────────
    from app.auth.routes      import auth
    from app.dashboard.routes import dashboard
    from app.community.routes import community
    from app.blog.routes      import blog
    from app.profile.routes   import profile
    from app.main.routes      import main

    app.register_blueprint(auth)
    app.register_blueprint(dashboard)
    app.register_blueprint(community)
    app.register_blueprint(blog)
    app.register_blueprint(profile)
    app.register_blueprint(main)

    # ── Custom Jinja Filters ──────────────────────────────────────────
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo

    @app.template_filter("to_ist")
    def to_ist_filter(value, fmt="%b %d, %Y at %I:%M %p IST"):
        if not value:
            return ""
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except Exception:
                return value
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        ist_time = value.astimezone(ZoneInfo("Asia/Kolkata"))
        return ist_time.strftime(fmt)

    # ── Create DB tables ─────────────────────────────────────────────
    with app.app_context():
        db.create_all()

    return app
