from flask import Flask, redirect, render_template, url_for, request, flash, g, session
from datetime import date
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Integer, String, Date, Text, Boolean

import random
import string
import hashlib
import binascii

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SomethingWhatNoOneWillGuess'

app.config.from_pyfile('config.cfg')

Base = declarative_base()

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Admin pass:
# user name: onp
# user pass: kMw


class users(db.Model):
    __tablename__ = 'users'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    name = db.Column(String(100))
    email = db.Column(String(100))
    password = db.Column(Text)
    is_active = db.Column(Boolean)
    is_admin = db.Column(Boolean)


class UserPass:
    def __init__(self, user='', password=''):
        self.user = user
        self.password = password
        self.email = ''
        self.is_admin = False
        self.is_active = False
        self.is_valid = False

    def hash_password(self):
        """Hash a password for storing."""
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac(
            'sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode(
            'utf-8'), salt.encode('ascii'),  100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_password(self):
        random_user = ''.join(random.choice(
            string.ascii_lowercase)for i in range(3))
        self.user = random_user

        password_characters = string.ascii_letters
        random_password = ''.join(random.choice(
            password_characters)for i in range(3))
        self.password = random_password

    def login_user(self):
        user_record = users.query.filter(users.name == self.user).first()

        if user_record is not None and self.verify_password(user_record.password, self.password):
            session['user'] = user_record.name
            if user_record.is_admin:
                session['is_admin'] = True
            return user_record
        else:
            self.user = None
            self.password = None
            return None

    def get_user_info(self):
        db_user = users.query.filter(users.name == self.user).first()

        if db_user == None:
            self.is_valid = False
            self.is_admin = False
            self.is_active = False
            self.email = ''
        elif db_user.is_active != 1:
            self.is_valid = False
            self.is_admin = False
            self.is_active = False
            self.email = db_user.email
        else:
            self.is_valid = True
            self.is_admin = db_user.is_admin
            self.is_active = db_user.is_active
            self.email = db_user.email


@app.route('/login', methods=['GET', 'POST'])
def login():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()

    if request.method == 'GET':
        return render_template('login.html', active_menu='login', login=login)
    else:
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']

        login = UserPass(user_name, user_pass)
        login_record = login.login_user()

        if login_record != None:
            session['user'] = user_name
            flash('Logon successful, welcome {}'.format(user_name))
            return redirect(url_for('index'))
        else:
            flash('Logon failed, try again')
            return render_template('login.html', active_menu='login', login=login)


@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user', None)
        flash('You are logged out')
    return redirect(url_for('login'))


@app.route('/init_app')
def init_app():
    db.create_all()

    active_admins = users.query.filter(
        users.is_active == True, users.is_admin == True).count()

    if active_admins > 0:
        flash('Application is already set-up. Nothing to do')
        return redirect(url_for('index'))

    user_pass = UserPass()
    user_pass.get_random_user_password()

    new_admin = users(name=user_pass.user, email='noone@nowhere.no',
                      password=user_pass.hash_password(), is_active=True, is_admin=True)  # type: ignore
    db.session.add(new_admin)
    db.session.commit()

    flash('User {} with password {} has been created'.format(
        user_pass.user, user_pass.password))
    return redirect(url_for('index'))


@app.route('/')
def index():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    return render_template('index.html', active_menu='home', login=login)


@app.route('/register', methods=['GET', 'POST'])
def register():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()

    message = None
    user = {}
    if request.method == 'GET':
        return render_template('register.html', active_menu='register', user=user, login=login)
    else:
        user['user_name'] = '' if 'user_name' not in request.form else request.form['user_name']
        user['email'] = '' if 'email' not in request.form else request.form['email']
        user['user_pass'] = '' if 'user_pass' not in request.form else request.form['user_pass']

        is_user_name_unique = (users.query.filter(
            users.name == user['user_name']).count() == 0)
        is_user_email_unique = (users.query.filter(
            users.name == user['email']).count() == 0)

        if user['user_name'] == '':
            message = 'Name cannot be empty'
        elif user['email'] == '':
            message = 'Email cannot be empty'
        elif user['user_pass'] == '':
            message = 'Password cannot be empty'
        elif not is_user_name_unique:
            message = 'User with name {} already exists'.format(
                user['user_name'])
        elif not is_user_email_unique:
            message = 'User with email {} already exists'.format(user['email'])

        if not message:
            user_pass = UserPass(user['user_name'], user['user_pass'])
            password_hash = user_pass.hash_password()

            new_user = users(name=user['user_name'], email=user['email'], password=password_hash,
                             is_active=True, is_admin=False)  # type: ignore
            db.session.add(new_user)
            db.session.commit()

            flash('User {} created'.format(user['user_name']))
            return redirect(url_for('index'))
        else:
            flash('Error: {}'.format(message))
            return render_template('register.html', active_menu='register', user=user, login=login)


@app.route('/repertoire')
def repertoire():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    return render_template('repertoire.html', active_menu='repertoire', login=login)


if __name__ == '__main__':
    app.run()
