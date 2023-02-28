from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, Email

class SignupForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email('e')], render_kw={"placeholder": "E-mail"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=32)], render_kw={"placeholder": "••••••••"})
    submit = SubmitField('Sign up')

class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message='Please enter an e-mail address in format: example@example.com')], render_kw={"placeholder": "E-mail"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=32)], render_kw={"placeholder": "••••••••"})
    submit = SubmitField('Log in')
    checkbox = BooleanField('Remember')

class ArtistForm(FlaskForm):
    artist = StringField(validators=[InputRequired()], render_kw={"placeholder": "Search for artist..."})
    submit = SubmitField('Add')