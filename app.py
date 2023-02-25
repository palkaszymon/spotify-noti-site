from flask import Flask, render_template, url_for, redirect, flash
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from neo4j import GraphDatabase
from dotenv import load_dotenv
from os import getenv
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = getenv('SECRET_KEY')
bcrypt = Bcrypt(app)

load_dotenv()
URI = getenv('NEO4J_URI')
USERNAME= getenv('NEO4J_USERNAME')
PASSWORD = getenv('NEO4J_PASSWORD')

dbdriver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader

def load_user(user_id):
    with dbdriver.session() as session:
        return session.execute_read(Neo4J.user_by_id, user_id)

class User():
    def __init__(self, email, password, id):
        self.id = id
        self.email = email
        self.password = password
    
    def is_active(self):
        return True
    def is_authenticated(self):
        return self._authenticated
    def is_anonymous(self):
        return False
    def is_admin(self):
        return self.admin
    def __repr__(self):
        return f'<Users:{self.email}>'
    def get_id(self):
        return (self.id)

class Neo4J():
    @staticmethod
    def find_email(tx, email):
        result = tx.run("""
MATCH (u:User {email: $email})
RETURN u.email
""", email=email)
        return [record['u.email'] for record in result]
    
    @staticmethod
    def create_user(tx, user):
        result = tx.run("""
MERGE (i:UserIds {value:"userid"}) ON CREATE SET i.user_id = 1 ON MATCH SET i.user_id = i.user_id + 1
MERGE (u:User {user_id:i.user_id, email: $email, password: $password, created_at: $current_time})
""", email=user.email, password=user.password, current_time=datetime.now().strftime("%d/%m/%Y %H:%M:%S")
)
        return result
    
    @staticmethod
    def user_by_id(tx, user_id):
        result = tx.run("""
MATCH (u:User {user_id: $user_id})
RETURN u.user_id, u.email, u.password
""", user_id=user_id)
        user = [(record['u.user_id'], record['u.email'], record['u.password']) for record in result]
        if user:
            return User(id=user[0][0], email=user[0][1], password=user[0][2])
        else: 
            return None
        
    @staticmethod
    def user_by_email(tx, email):
        result = tx.run("""
MATCH (u:User {email: $email})
RETURN u.user_id, u.email, u.password
""", email=email)
        user = [(record['u.user_id'], record['u.email'], record['u.password']) for record in result]
        if user:
            return User(id=user[0][0], email=user[0][1], password=user[0][2])
        else: 
            return None

class SignupForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email('e')], render_kw={"placeholder": "E-mail"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=32)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Sign up')

def email_unique(email):
    status = True
    with dbdriver.session() as session:
        if session.execute_read(Neo4J.find_email, email):
            status = False
        return status

class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message='Please enter an e-mail address in format: example@example.com')], render_kw={"placeholder": "E-mail"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=32)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Log in')

@app.route('/')
def main():
    return render_template('main.html.jinja')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with dbdriver.session() as session:
            user = session.execute_read(Neo4J.user_by_email, form.email.data)
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('main'))
                else:
                    flash('Wrong password.')
            else:
                flash('No account associated with that e-mail.')
    return render_template('login.html.jinja', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        if email_unique(form.email.data):
            new_user = User(id=None, email=form.email.data, password=hashed_password)
            with dbdriver.session() as session:
                session.execute_write(Neo4J.create_user, new_user)
            return redirect(url_for('login'))
        else:
            flash('This e-mail is already in use. Please choose another one.')
    return render_template('signup.html.jinja', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('main'))

if __name__ == '__main__':
    app.run(debug=True)