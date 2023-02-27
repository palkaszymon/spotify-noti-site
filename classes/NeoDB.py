from datetime import datetime
from classes.User import User
from flask_login import current_user

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

    @staticmethod  
    def create_user_artist_rel(tx, artist_name):
        result = tx.run("""                       
MATCH (u:User {user_id: $user_id}), (a:Artist {artist_name: $artist_name})
MERGE (u)-[:FOLLOWS]->(a)
""", user_id=current_user.id, artist_name=artist_name)
    
    @staticmethod
    def get_users_artists(tx):
        result = tx.run("""
MATCH (u:User {user_id: $id})--(a:Artist)
RETURN a
""", id=current_user.id)
        return [node['a'] for node in [record.data('a') for record in result]]
    
    @staticmethod
    def get_artist_latest(tx, id):
        result = tx.run("""
MATCH (a:Artist {artist_id: $id})--(al:Album)
WITH max(al.release_date) as max, a as a
MATCH (al:Album)--(a) WHERE al.release_date=max
RETURN al
""", id=id)
        return [node['al'] for node in [record.data('al') for record in result]]
    
    @staticmethod
    def get_all_artists(tx):
        result = tx.run("""
MATCH (a:Artist)
RETURN a.artist_name AS name
""")
        return [record['name'] for record in result]