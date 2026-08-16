from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app import db
from app.models import User

profile = Blueprint("profile", __name__, url_prefix="/profile")


@profile.route("/<username>")
def view(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template("profile/view.html", user=user)


@profile.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    if request.method == "POST":
        bio = request.form.get("bio", "").strip()
        current_user.bio = bio
        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("profile.view", username=current_user.username))

    return render_template("profile/edit.html")


@profile.route("/leaderboard")
def leaderboard():
    top_users = User.query.order_by(User.scan_count.desc()).limit(20).all()
    return render_template("profile/leaderboard.html", users=top_users)