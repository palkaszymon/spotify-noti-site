from base64 import b64encode
from requests import get, post
import json
from urllib.parse import quote
from datetime import datetime, date
from dotenv import load_dotenv
from os import getenv

load_dotenv()
CLIENT_ID = getenv('CLIENT_ID')
CLIENT_SECRET = getenv('CLIENT_SECRET')

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

    def get_response_data(self, mode, param=None):
        if mode == 'search':
            url = f"https://api.spotify.com/v1/search?query={param}&type=artist&market=PL"
        elif mode == 'artist':
            url = f"https://api.spotify.com/v1/artists/{param}/albums?include_groups=album%2Csingle&market=PL" 
        response = get(url, data=None, headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.get_oauth_token()}"
        })
        return response.json()
    
    def artist_search(self, name):
        data = self.get_response_data('search', quote(name))['artists']['items'][0]
        return {'artist_name': data['name'], 'artist_id': data['id'], 'img_url': data['images'][1]['url']}

class SpotifyArtist(Spotify):
    def __init__(self, id):
        self.id = id
        self.response = self.get_response_data('artist', self.id)

    def get_artist_list(self, track_id):
        return [{'artist_name': item['artists'][i]['name'], 'artist_id': item['artists'][i]['id']} for item in self.response['items'] for i in range(len(item['artists'])) if item['id'] == track_id]
    
    def get_items(self):
        return [{'id': item['id'], 'name': item['name'], 'type': item['album_type'], 'artists': self.get_artist_list(item['id']), 'release_date': item['release_date']} for item in self.response['items']]
    
    # Sorts the albums by release date descending, and returns the newest 3
    def get_final_items(self):
        albums = sorted(self.get_items(), key = lambda x: datetime.strptime(self.check_date(x['release_date']), '%Y-%m-%d'), reverse=True)
        return [albums[i] for i in range(len(albums)-1) if albums[i]['name'] != albums[i+1]['name']][:3]
    
    @staticmethod
    def check_date(date_text):
        check_date = None
        try:
            date.fromisoformat(date_text)
            check_date = date_text
        except ValueError:
            if len(date_text) == 4:
                check_date = f"{date_text}-01-01"
        return check_date