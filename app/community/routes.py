from datetime import datetime

from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from flask_socketio import emit, join_room

from app import db, socketio
from app.models import Message

community = Blueprint("community", __name__, url_prefix="/community")


@community.route("/")
@login_required
def chat():
    recent = Message.query.filter_by(room="general") \
                           .order_by(Message.created_at.desc()).limit(50).all()
    recent.reverse()
    return render_template("community/chat.html", messages=recent)


@socketio.on("join")
def handle_join(data):
    room = data.get("room", "general")
    join_room(room)
    emit("status", {"msg": f"{current_user.username} joined the chat."}, room=room)


@socketio.on("send_message")
def handle_message(data):
    room    = data.get("room", "general")
    content = data.get("content", "").strip()

    if not content:
        return

    msg = Message(user_id=current_user.id, room=room, content=content)
    db.session.add(msg)
    db.session.commit()

    emit("new_message", {
        "username":  current_user.username,
        "content":   content,
        "timestamp": msg.created_at.strftime("%H:%M"),
    }, room=room)