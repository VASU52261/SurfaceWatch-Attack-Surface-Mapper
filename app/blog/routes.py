from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app import db
from app.models import Post

blog = Blueprint("blog", __name__, url_prefix="/blog")


@blog.route("/")
def index():
    posts = Post.query.filter_by(published=True) \
                       .order_by(Post.created_at.desc()).all()
    return render_template("blog/index.html", posts=posts)


@blog.route("/post/<int:post_id>")
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template("blog/post.html", post=post)


@blog.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        title   = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        tags    = request.form.get("tags", "").strip()

        if not title or not content:
            flash("Title and content are required.", "danger")
            return redirect(url_for("blog.create"))

        post = Post(user_id=current_user.id, title=title, content=content, tags=tags)
        db.session.add(post)
        db.session.commit()

        flash("Post published!", "success")
        return redirect(url_for("blog.view_post", post_id=post.id))

    return render_template("blog/create.html")