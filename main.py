from flask import Flask, render_template, redirect, url_for, flash, abort
from functools import wraps
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor,CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ["BLOG_SECRET_KEY"]
ckeditor = CKEditor(app)
boootstrap = Bootstrap5(app)
login_manager = LoginManager(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

#LOAD USER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorator_fn(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorator_fn


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ["BLOG_DATABASE_URL"]
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = db.relationship('BlogPost', back_populates='author')
    comments = db.relationship("Comment", back_populates='name')


class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship("User", back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship("Comment", back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.relationship("User", back_populates='comments')
    post_id = db.Column(db.String, db.ForeignKey('blog_post.id'))
    parent_post = db.relationship("BlogPost", back_populates='comments')


#FORMS
class RegisterForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()], render_kw={'class': 'mb-5'})
    password = PasswordField(label='Password', validators=[DataRequired()], render_kw={'class': 'mb-5'})
    name = StringField(label='Name', validators=[DataRequired()], render_kw={'class': 'mb-5'})
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()], render_kw={'class': 'mb-5'})
    password = PasswordField(label='Password', validators=[DataRequired()], render_kw={'class': 'mb-5'})
    submit = SubmitField("Log in")


class CommentForm(FlaskForm):
    comment = CKEditorField(label='Add Comment', validators=[DataRequired()], render_kw={'class': 'mb-5'})
    submit = SubmitField("Add Comment")


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, login_status=current_user.is_authenticated, user=current_user)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_exist = User.query.filter_by(email=form.email.data).first()
        if not user_exist:
            new_user = User(
                email=form.email.data,
                password=generate_password_hash(form.password.data, salt_length=8),
                name=form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash("User already exist, Please login")
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('Email does not exist')
            return redirect(url_for('login'))
        elif check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('You have entered wrong password')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    comment_form = CommentForm()
    comments = Comment.query.filter_by(post_id=post_id).all()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            comment = comment_form.comment.data
            if "<p>&nbsp;</p>" in comment:
                comment = comment.replace('<p>&nbsp;</p>', "")
                comment = comment.replace(' ', '')
            new_comment = Comment(text=comment, name=current_user, parent_post=requested_post)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("You need to login to comment")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, login_status=current_user.is_authenticated, form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", login_status=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", login_status=current_user.is_authenticated)


@app.route("/new-post", methods=['POST', "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, login_status=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = post.author
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, login_status=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
