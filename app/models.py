from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    avatar        = db.Column(db.String(200), default="default.png")
    bio           = db.Column(db.Text, default="")
    role          = db.Column(db.String(20),  default="user")  # user / admin
    joined_at     = db.Column(db.DateTime,    default=datetime.utcnow)
    scan_count    = db.Column(db.Integer,     default=0)

    scans         = db.relationship("Scan",    backref="owner",  lazy=True)
    posts         = db.relationship("Post",    backref="author", lazy=True)
    messages      = db.relationship("Message", backref="sender", lazy=True)
    notifications = db.relationship("Notification", backref="user", lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"


class Scan(db.Model):
    id         = db.Column(db.Integer,  primary_key=True)
    user_id    = db.Column(db.Integer,  db.ForeignKey("user.id"), nullable=False)
    target     = db.Column(db.String(200), nullable=False)
    status     = db.Column(db.String(20),  default="pending")  # pending/running/done/failed
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)
    finished_at= db.Column(db.DateTime,    nullable=True)
    result_file= db.Column(db.String(200), nullable=True)   # path to JSON file
    node_count = db.Column(db.Integer,     default=0)
    edge_count = db.Column(db.Integer,     default=0)
    risk_score = db.Column(db.Float,       default=0.0)

    def __repr__(self):
        return f"<Scan {self.target} [{self.status}]>"


class Post(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title      = db.Column(db.String(200), nullable=False)
    content    = db.Column(db.Text,        nullable=False)
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)
    updated_at = db.Column(db.DateTime,    default=datetime.utcnow)
    published  = db.Column(db.Boolean,     default=True)
    tags       = db.Column(db.String(200), default="")

    def __repr__(self):
        return f"<Post {self.title}>"


class Message(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    room       = db.Column(db.String(50),  default="general")
    content    = db.Column(db.Text,        nullable=False)
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)

    def __repr__(self):
        return f"<Message by {self.user_id}>"


class Notification(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message    = db.Column(db.String(300), nullable=False)
    link       = db.Column(db.String(200), default="/")
    read       = db.Column(db.Boolean,     default=False)
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.message[:30]}>"
