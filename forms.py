from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, EqualTo, Email, Length
from wtforms import StringField, PasswordField, EmailField, SubmitField, SelectField, DateField
from flask_ckeditor import CKEditorField


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Register Me 😎")


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login 🕵️‍♂️")


class ForgotPasswordForm(FlaskForm):
    email = EmailField("Enter your Registered Email", validators=[DataRequired()])
    submit = SubmitField("Send")


class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm New Password", validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Reset Password")


class OtpForm(FlaskForm):
    otp = StringField("Enter OTP", validators=[DataRequired()])
    submit = SubmitField("Submit")


class VideoDataForm(FlaskForm):
    choices = [
        ('1', 'Python'),
        ('2', 'HTML'),
        ('3', 'CSS'),
        ('4', 'SQL'),
        ('5', 'Data Science'),
    ]
    name = StringField("Name of the course(Course Category)", validators=[DataRequired()])
    title = StringField("Title", validators=[DataRequired()])
    description = StringField("Description", validators=[DataRequired()])
    category = SelectField("Course Category", choices=choices)
    image_url = StringField("Thumbnail Image Url", validators=[DataRequired()])
    source = StringField("Video Data Source(HQ video)", validators=[DataRequired()])
    source2 = StringField("Video Data Source(LQ video)", validators=[DataRequired()])
    date = DateField("Upload Date", validators=[DataRequired()])
    credit = StringField("Credits to", validators=[DataRequired()])
    submit = SubmitField("Upload")


class CourseDetails(FlaskForm):
    choices = [
        ('1', 'Python'),
        ('2', 'HTML'),
        ('3', 'SQL'),
        ('4', 'Data Science'),
    ]
    category = SelectField("Course Category", choices=choices)
    body = CKEditorField("New Updates", validators=[DataRequired()])
    submit = SubmitField("Upload")


class UserNotes(FlaskForm):
    body = CKEditorField("Make Notes", validators=[DataRequired()])
    submit = SubmitField("Save", validators=[DataRequired()])