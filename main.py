from flask import Flask, render_template, redirect, url_for, session, request, abort, flash
from flask_bootstrap import Bootstrap5
from forms import RegisterForm, LoginForm, ResetPasswordForm, ForgotPasswordForm, OtpForm, VideoDataForm, CourseDetails, \
    UserNotes
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import mapped_column, Mapped, DeclarativeBase, relationship
from sqlalchemy import Integer, String
from flask_login import LoginManager, login_user, logout_user, UserMixin, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer
import smtplib
import random
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
Bootstrap5(app)
app.secret_key = os.environ.get("coffee_key")
serializer = URLSafeTimedSerializer(app.secret_key)
ckeditor = CKEditor(app)

author_email = os.environ.get("myemail")
author_password = os.environ.get("gm_pass")

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class Base(DeclarativeBase):
    pass


app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DB_URI3", "sqlite:///main.db")

db = SQLAlchemy(model_class=Base)
db.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='monsterid',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


def generate_otp():
    return str(random.randint(100000, 999999))


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    notes = relationship("Note", back_populates='author')


class Note(Base):
    __tablename__ = "note"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="notes")
    notes_data: Mapped[str] = mapped_column(String, nullable=False)


class Videos(db.Model):
    __tablename__ = "videos"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    source2: Mapped[str] = mapped_column(String, nullable=False)
    image_url: Mapped[str] = mapped_column(String, nullable=False)
    date: Mapped[str] = mapped_column(String, nullable=False)
    credit: Mapped[str] = mapped_column(String, nullable=False)


class Updates(db.Model):
    __tablename__ = 'updates'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category: Mapped[str] = mapped_column(String, nullable=False)
    new_data: Mapped[str] = mapped_column(String, nullable=False)


with app.app_context():
    db.create_all()


def send_mail(recipient, subject, body):
    with smtplib.SMTP("smtp.gmail.com") as connect:
        connect.starttls()
        connect.login(user=author_email, password=author_password)
        message = f"Subject: {subject}\n\n{body}"
        connect.sendmail(
            from_addr=author_email,
            to_addrs=recipient,
            msg=message,
        )


def verify_password(user):
    token = serializer.dumps(user.email, salt=os.environ.get('dev_key'))
    reset_url = url_for('reset_password', token=token, _external=True)
    subject = "Password Reset Request"
    body = (
        f"Hello {user.name},\nWe've received a request to reset your password. To proceed, please follow the link below:\n{reset_url}\nIf you didn't request this change, you can safely ignore this message.Best regards,\nDev Singh")
    send_mail(user.email, subject, body)


def admin_only(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.email != author_email:
                return abort(403)
        else:
            return abort(403)
        return f(*args, **kwargs)

    return decorated


def admin_member(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return abort(403)
        return f(*args, **kwargs)

    return decorated


@app.route("/")
def home():
    all_data = db.session.execute(db.select(Videos)).scalars().all()
    return render_template('new_index.html', all_data=all_data, current_user=current_user)


@app.route('/all_course/<category_id>', methods=["POST", "GET"])
def all_topic(category_id):
    category_course_data = db.session.execute(db.select(Videos).where(Videos.category == category_id)).scalars().all()
    return render_template('all_course.html', data=category_course_data, current_user=current_user)


@app.route("/delete_course/<id_data>", methods=["POST", "GET"])
@admin_only
def delete(id_data):
    course_to_delete = db.session.execute(db.select(Videos).where(Videos.id == id_data)).scalar()
    db.session.delete(course_to_delete)
    db.session.commit()
    return redirect(url_for("home"))


@app.route("/profile", methods=["POST", "GET"])
@admin_member
def profile():
    all_data = db.session.execute(db.select(Note).where(Note.author_id == current_user.id)).scalars().all()
    return render_template("profile.html", current_user=current_user, data=all_data)


@app.route("/edit_profile", methods=['POST'])
@admin_member
def edit_profile():
    if request.method == 'POST':
        new_name = request.form.get('name')
        new_email = request.form.get('email')
        current_user.name = new_name
        current_user.email = new_email
        db.session.commit()
        return redirect(url_for('profile'))


@app.route("/admin_upload", methods=["POST", "GET"])
@admin_only
def admin_upload():
    form = VideoDataForm()
    if form.validate_on_submit():
        new_data = Videos(
            name=form.name.data,
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            source=form.source.data,
            source2=form.source2.data,
            credit=form.credit.data,
            date=form.date.data,
            image_url=form.image_url.data,
        )
        db.session.add(new_data)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("adminupload.html", form=form, current_user=current_user)


@app.route("/login", methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user:
            flash("Sorry, this email doesn't exist. Please register an account to continue.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Entered Password is Incorrect")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html', form=form, current_user=current_user)


@app.route("/register", methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email_data = form.email.data
        user = db.session.execute(db.select(User).where(User.email == email_data)).scalar()
        if user:
            flash("The email provided already exists. Please use a different email address.")
            return redirect(url_for('register'))
        else:
            otp = generate_otp()
            subject = "OTP for Registration"
            body = f"Dear learner you OTP for registration is {otp}.\n Keep Learning"
            send_mail(email_data, subject, body)
            session['otp'] = otp
            session['name'] = form.name.data
            session['email'] = email_data
            session['password'] = form.password.data
            return redirect(url_for('verify_otp'))
    return render_template('register.html', form=form, current_user=current_user)


@app.route('/verify_otp', methods=["POST", "GET"])
def verify_otp():
    if 'otp' not in session:
        flash('OTP not found. Please register first.', 'danger')
        return redirect(url_for('register'))
    form = OtpForm()
    if form.validate_on_submit():
        entered_otp = form.otp.data
        created_otp = session.pop("otp", None)
        if entered_otp == created_otp:
            name = session.pop('name', None)
            email = session.pop('email', None)
            password = session.pop('password', None)

            new_password = generate_password_hash(
                password=password,
                method='pbkdf2:sha256',
                salt_length=8
            )

            new_user = User(name=name, email=email, password=new_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify.html', form=form)


@app.route('/learn_data/<course_id>', methods=["POST", "GET"])
@admin_member
def learn(course_id):
    form = UserNotes()
    detailed_course = db.session.execute(db.select(Videos).where(Videos.id == course_id)).scalar()
    if form.validate_on_submit():
        new_data = Note(
            notes_data=form.body.data,
            author_id=current_user.id,
        )
        db.session.add(new_data)
        db.session.commit()
        return redirect(url_for('learn', course_id=detailed_course.id))
    return render_template('details.html', data=detailed_course, current_user=current_user, form=form)


@app.route("/note_delete/<note_id>", methods=["POST", "GET"])
def delete_note(note_id):
    note = db.get_or_404(Note, note_id)
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('profile'))


@app.route('/forgot_password', methods=['POST', 'GET'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        old_user = User.query.filter_by(email=email).first()
        if old_user:
            verify_password(old_user)
            flash("An email has been dispatched to your registered email address containing instructions to reset your password.")
            return redirect(url_for('forgot_password'))
        else:
            flash(
                "This email is not registered with us. Please check the email address or consider registering if you are new to our platform.")
            return redirect(url_for('forgot_password'))
    return render_template('forgot.html', form=form)


@app.route('/reset_password/<token>', methods=['POST', 'GET'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt=os.environ.get("dev_key"), max_age=3600)
        user = User.query.filter_by(email=email).first()
        if not user:
            return redirect(url_for('login'))
        form = ResetPasswordForm()
        if form.validate_on_submit():
            new_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
            user.password = new_password
            db.session.commit()
            return redirect(url_for('home'))
    except:
        return redirect(url_for('login'))
    return render_template("reset.html", form=form)


# ------------------------------------------------------
@app.route("/python", methods=["POST", "GET"])
def python_data():
    new_data = db.session.execute(db.select(Updates).where(Updates.category == 1)).scalar()
    return render_template("python.html", data=new_data, current_user=current_user)


@app.route("/html", methods=["POST", "GET"])
def html_data():
    new_data = db.session.execute(db.select(Updates).where(Updates.category == 2)).scalar()
    return render_template("html_html.html", data=new_data, current_user=current_user)


@app.route("/sql_my", methods=["POST", "GET"])
def sql_data():
    new_data = db.session.execute(db.select(Updates).where(Updates.category == 3)).scalar()
    return render_template("data_sql.html", data=new_data, current_user=current_user)


@app.route("/science_data", methods=["POST", "GET"])
def learn_data():
    new_data = db.session.execute(db.select(Updates).where(Updates.category == 4)).scalar()
    return render_template("data_science.html", data=new_data, current_user=current_user)


@app.route('/add_new_content', methods=['POST', 'GET'])
@admin_only
def add_new_content():
    form = CourseDetails()
    if form.validate_on_submit():
        add = Updates(
            new_data=form.body.data,
            category=form.category.data,
        )
        db.session.add(add)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add_new_data.html', form=form, current_user=current_user)


@app.route('/edit_content/<category>', methods=['POST', 'GET'])
@admin_only
def edit_content(category):
    post = Updates.query.filter_by(category=category).first_or_404()
    edit_form = CourseDetails()
    if edit_form.validate_on_submit():
        post.new_data = edit_form.body.data
        post.category = edit_form.category.data
        db.session.commit()
        return redirect(url_for('python_data'))
    elif request.method == 'GET':
        edit_form.body.data = post.new_data
        edit_form.category.data = post.category
    return render_template('add_new_data.html', form=edit_form, current_user=current_user)


@app.route("/logout")
def remove_me():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=False)
