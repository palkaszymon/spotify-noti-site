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