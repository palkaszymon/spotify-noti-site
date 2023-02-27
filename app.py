from flask import Flask, render_template, url_for, redirect, flash, request
from flask_wtf import FlaskForm
from flask_login import login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, Email
from neo4j import GraphDatabase
from dotenv import load_dotenv
from os import getenv
from datetime import datetime
from passlib.hash import sha512_crypt
from passlib.utils import to_bytes, to_unicode
import json
from base64 import b64encode
from requests import get, post
from urllib.parse import quote

app = Flask(__name__)
app.config['SECRET_KEY'] = getenv('SECRET_KEY')

load_dotenv()
URI = getenv('NEO4J_URI')
USERNAME= getenv('NEO4J_USERNAME')
PASSWORD = getenv('NEO4J_PASSWORD')
CLIENT_ID = getenv('CLIENT_ID')
CLIENT_SECRET = getenv('CLIENT_SECRET')

dbdriver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader

def load_user(user_id):
    with dbdriver.session() as session:
        return session.execute_read(Neo4J.user_by_id, user_id)

class Spotify():
    def get_oauth_token(self):
        auth_string = CLIENT_ID + ':' + CLIENT_SECRET
        auth_b64 = str(b64encode(auth_string.encode('UTF-8')), 'UTF-8')
        url = 'https://accounts.spotify.com/api/token'
        headers = {
            "Authorization": "Basic " + auth_b64,
            "Content-Type" : "application/x-www-form-urlencoded"
        }
        data = {"grant_type": "client_credentials"}

        result = post(url, headers=headers, data=data)
        return json.loads(result.content)['access_token']

    def get_response_data(self, name):
        url = f"https://api.spotify.com/v1/search?query={name}&type=artist&market=PL"
        response = get(url, data=None, headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.get_oauth_token()}"
        })
        return response.json()
    
    def artist_search(self, name):
        data = self.get_response_data(quote(name))['artists']['items'][0]
        return {'artist_name': data['name'], 'artist_id': data['id'], 'img_url': data['images'][1]['url']}

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
   
    @staticmethod
    def create_artist(tx, artist):
        result = tx.run("""                       
MATCH (u:User {user_id: $user_id})
MERGE (a:Artist {artist_id: $artist_id, artist_name: $artist_name, img_url: $img_url})
MERGE (u)-[:FOLLOWS]->(a)
""", user_id=current_user.id, artist_id=artist['artist_id'], artist_name=artist['artist_name'], img_url=artist['img_url'])
        
    def create_user_artist_rel(tx, artist_name):
        result = tx.run("""                       
MATCH (u:User {user_id: $user_id}), (a:Artist {artist_name: $artist_name})
MERGE (u)-[:FOLLOWS]->(a)
""", user_id=current_user.id, artist_name=artist_name)
    
    def get_users_artists(tx):
        result = tx.run("""
MATCH (u:User {user_id: $id})--(a:Artist)
RETURN a
""", id=current_user.id)
        return [node['a'] for node in [record.data('a') for record in result]]
    
    def get_artist_latest(tx, id):
        result = tx.run("""
MATCH (a:Artist {artist_id: $id})--(al:Album)
WITH max(al.release_date) as max, a as a
MATCH (al:Album)--(a) WHERE al.release_date=max
RETURN al
""", id=id)
        return [node['al'] for node in [record.data('al') for record in result]]
    
    def get_all_artists(tx):
        result = tx.run("""
MATCH (a:Artist)
RETURN a.artist_name AS name
""")
        return [record['name'] for record in result]

class SignupForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email('e')], render_kw={"placeholder": "E-mail"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=32)], render_kw={"placeholder": "••••••••"})
    submit = SubmitField('Sign up')

class ArtistForm(FlaskForm):
    artist = StringField(render_kw={"placeholder": "Search for artist..."})
    submit = SubmitField('Add')

def email_unique(email):
    status = True
    with dbdriver.session() as session:
        if session.execute_read(Neo4J.find_email, email):
            status = False
        return status

class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message='Please enter an e-mail address in format: example@example.com')], render_kw={"placeholder": "E-mail"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=32)], render_kw={"placeholder": "••••••••"})
    submit = SubmitField('Log in')
    checkbox = BooleanField('Remember')

@app.route('/')
def main():
    return render_template('main.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with dbdriver.session() as session:
            user = session.execute_read(Neo4J.user_by_email, form.email.data)
            if user:
                if sha512_crypt.verify(form.password.data, to_unicode(user.password)):
                    if form.checkbox.data:
                        remember=True
                    else:
                        remember=False
                    login_user(user, remember)
                    return redirect(url_for('main'))
                else:
                    flash('Wrong password.')
            else:
                flash('No account associated with that e-mail.')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = sha512_crypt.hash(form.password.data)
        email = form.email.data
        if email_unique(email):
            new_user = User(id=None, email=email, password=to_bytes(hashed_password))
            with dbdriver.session() as session:
                session.execute_write(Neo4J.create_user, new_user)
                log_user = session.execute_read(Neo4J.user_by_email, email)
            login_user(log_user, hashed_password)
            return redirect(url_for('artists'))
        else:
            flash('This e-mail is already in use. Please choose another one.')
    return render_template('signup.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('main'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    return render_template('contact.html')

@app.route('/artists', methods=['GET', 'POST'])
def artists():
    if current_user.is_authenticated:
        with dbdriver.session() as session:
            artists = session.execute_read(Neo4J.get_users_artists)
            artist_list = [{'artist': artist, 'newest': newest} for artist in artists for newest in session.execute_read(Neo4J.get_artist_latest, artist['artist_id'])]
            return render_template('artists.html', artists=artist_list)
    else:
        return login_manager.unauthorized()

@app.route('/artists/add', methods=['GET', 'POST'])
def add():
    if current_user.is_authenticated:
        with dbdriver.session() as session:
            form = ArtistForm()
            names = session.execute_read(Neo4J.get_all_artists)
            users_artists = session.execute_read(Neo4J.get_users_artists)
            count = len(users_artists)
            if form.validate_on_submit():
                artist = form.artist.data
                if count <20:
                    if artist not in names:
                        new_artist = Spotify().artist_search(form.artist.data)
                        session.execute_write(Neo4J.create_artist, new_artist)
                    else:
                        session.execute_write(Neo4J.create_user_artist_rel, artist)
                    count+=1
                    flash(f"{artist} added succesfully!")
                else:
                    flash(f"You can't add more artists. Right now the user limit is 20.")
            return render_template('add.html', form=form, data=json.dumps(names), users_artists=users_artists, count=count)
    else:
        return login_manager.unauthorized()

if __name__ == '__main__':
    app.run(debug=True)
    # with dbdriver.session() as session:
    # dbdriver.close()
