from flask import session
from database_connection import Users, ActiveSessions
import hashlib
import binascii
import uuid
import random
import string
from user import app, db


class UserPass:
    def __init__(self, user='', password=''):
        self.id = None
        self.user = user
        self.password = password
        self.email = ''
        self.is_admin = False
        self.is_active = False
        self.is_valid = False

    def hash_password(self):
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac(
            'sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(self, stored_password, provided_password):
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode(
            'utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_password(self):
        random_user = ''.join(random.choice(string.ascii_lowercase)
                              for _ in range(3))
        self.user = random_user

        password_characters = string.ascii_letters
        random_password = ''.join(random.choice(
            password_characters) for _ in range(3))
        self.password = random_password

    def login_user(self):
        user_record = Users.query.filter(Users.name == self.user).first()

        if user_record and self.verify_password(user_record.password, self.password):
            session['user'] = user_record.name
            session['session_id'] = str(uuid.uuid4())
            new_session = ActiveSessions(
                # type: ignore
                user_id=user_record.id, session_id=session['session_id'])
            db.session.add(new_session)

            user_record.is_active = True
            db.session.commit()

            if user_record.is_admin:
                session['is_admin'] = True
            return user_record
        else:
            self.user = None
            self.password = None
            return None

    def get_user_info(self):
        db_user = Users.query.filter(Users.name == self.user).first()

        if not db_user:
            self.id = None
            self.is_valid = False
            self.is_admin = False
            self.is_active = False
            self.email = ''
        elif not db_user.is_active:
            self.id = None
            self.is_valid = False
            self.is_admin = False
            self.is_active = False
            self.email = db_user.email
        else:
            self.id = db_user.id
            self.is_valid = True
            self.is_admin = db_user.is_admin
            self.is_active = db_user.is_active
            self.email = db_user.email


@app.context_processor
def inject_login():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    return dict(login=login)
