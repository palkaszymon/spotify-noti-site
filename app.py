from flask import Flask, render_template, url_for, redirect, flash, request
from flask_login import login_user, LoginManager, logout_user, current_user
from neo4j import GraphDatabase
from dotenv import load_dotenv
from os import getenv
from passlib.hash import sha512_crypt
from passlib.utils import to_bytes, to_unicode
import json
from classes.User import User
from classes.NeoDB import Neo4J
from classes.Spotify import *
from classes.Forms import *

load_dotenv()
URI = getenv('NEO4J_URI')
USERNAME= getenv('NEO4J_USERNAME')
PASSWORD = getenv('NEO4J_PASSWORD')

app = Flask(__name__)
app.config['SECRET_KEY'] = getenv('SECRET_KEY')
dbdriver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    with dbdriver.session() as session:
        return session.execute_read(Neo4J.user_by_id, user_id)

def email_unique(email):
    status = True
    with dbdriver.session() as session:
        if session.execute_read(Neo4J.find_email, email):
            status = False
        return status

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
            print(artist_list)
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
                        id = new_artist['artist_id']
                        session.execute_write(Neo4J.create_artist, new_artist)
                        for album in SpotifyArtist(id).get_final_items():
                            session.execute_write(Neo4J.create_album, album, id)
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