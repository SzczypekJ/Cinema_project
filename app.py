from sqlalchemy import Float
from flask import Flask, redirect, render_template, url_for, request, flash, g, session
from datetime import date
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Integer, String, Date, Text, Boolean, Float, DateTime
from collections import defaultdict

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
# user name: ewm
# user pass: uch


class Users(db.Model):
    __tablename__ = 'Users'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    name = db.Column(String(100), nullable=False)
    email = db.Column(String(100), nullable=False, unique=True)
    password = db.Column(Text, nullable=False)
    is_active = db.Column(Boolean, default=False)
    is_admin = db.Column(Boolean, default=False)


class GuestTokens(db.Model):
    __tablename__ = 'GuestTokens'
    token_id = db.Column(Integer, primary_key=True, autoincrement=True)
    is_active = db.Column(Boolean, default=False)
    created_at = db.Column(DateTime, default=datetime.now)


class Movies(db.Model):
    __tablename__ = 'Movies'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    title = db.Column(String(255), nullable=False)
    duration = db.Column(Integer, nullable=False)
    director = db.Column(String(100))
    description = db.Column(Text)
    photo = db.Column(String(255))


class Rooms(db.Model):
    __tablename__ = 'Rooms'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    name = db.Column(String(100), nullable=False)
    capacity = db.Column(Integer, nullable=False)


class RoomSections(db.Model):
    __tablename__ = 'RoomSections'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    room_id = db.Column(Integer, db.ForeignKey('Rooms.id'), nullable=False)
    room = db.relationship(
        'Rooms', backref=db.backref('roomsections', lazy=True))
    section_type = db.Column(String(50), nullable=False)
    capacity = db.Column(Integer, nullable=False)
    num_rows = db.Column(Integer, nullable=False)
    seats_per_row = db.Column(Integer, nullable=False)
    price_multiplier = db.Column(Integer, nullable=False)


class Seats(db.Model):
    __tablename__ = 'Seats'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    room_section_id = db.Column(Integer, db.ForeignKey(
        'RoomSections.id'), nullable=False)
    room_section = db.relationship(
        'RoomSections', backref=db.backref('seats', lazy=True))
    row_number = db.Column(Integer, nullable=False)
    seat_number = db.Column(Integer, nullable=False)


class Showtimes(db.Model):
    __tablename__ = 'Showtimes'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    movie_id = db.Column(Integer, db.ForeignKey('Movies.id'), nullable=False)
    movie = db.relationship(
        'Movies', backref=db.backref('showtimes', lazy=True))
    room_id = db.Column(Integer, db.ForeignKey('Rooms.id'), nullable=False)
    room = db.relationship('Rooms', backref=db.backref('showtimes', lazy=True))
    start_time = db.Column(DateTime, nullable=False)
    end_time = db.Column(DateTime, nullable=False)
    type = db.Column(String(20), nullable=False)
    language = db.Column(String(50), nullable=False)


class Bookings(db.Model):
    __tablename__ = 'Bookings'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(Integer, db.ForeignKey('Users.id'), nullable=False)
    user = db.relationship('Users', backref=db.backref('bookings', lazy=True))
    token_id = db.Column(Integer, db.ForeignKey('GuestTokens.token_id'))
    token = db.relationship(
        'GuestTokens', backref=db.backref('bookings', lazy=True))
    showtime_id = db.Column(Integer, db.ForeignKey(
        'Showtimes.id'), nullable=False)
    showtime = db.relationship(
        'Showtimes', backref=db.backref('bookings', lazy=True))
    seat_id = db.Column(Integer, db.ForeignKey('Seats.id'), nullable=False)
    seat = db.relationship('Seats', backref=db.backref('bookings', lazy=True))
    status = db.Column(String(20))
    created_at = db.Column(DateTime, default=datetime.now)


class RoomBookings(db.Model):
    __tablename__ = 'RoomBookings'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    room_id = db.Column(Integer, db.ForeignKey('Rooms.id'), nullable=False)
    room = db.relationship(
        'Rooms', backref=db.backref('room_bookings', lazy=True))
    user_id = db.Column(Integer, db.ForeignKey('Users.id'), nullable=False)
    user = db.relationship(
        'Users', backref=db.backref('room_bookings', lazy=True))
    start_time = db.Column(DateTime, nullable=False)
    end_time = db.Column(DateTime, nullable=False)
    status = db.Column(String(20))
    created_at = db.Column(DateTime, default=datetime.now)


class Payments(db.Model):
    __tablename__ = 'Payments'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    booking_id = db.Column(Integer, db.ForeignKey('Bookings.id'))
    booking = db.relationship(
        'Bookings', backref=db.backref('payments', lazy=True))
    room_booking_id = db.Column(Integer, db.ForeignKey('RoomBookings.id'))
    room_booking = db.relationship(
        'RoomBookings', backref=db.backref('payments', lazy=True))
    amount = db.Column(Float, nullable=False)
    status = db.Column(String(20))
    payment_method = db.Column(String(50))
    transaction_id = db.Column(String(100))
    created_at = db.Column(DateTime, default=datetime.now)


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
            # type: ignore
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
        user_record = Users.query.filter(Users.name == self.user).first()

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
        db_user = Users.query.filter(Users.name == self.user).first()

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

    active_admins = Users.query.filter(
        Users.is_active == True, Users.is_admin == True).count()

    if active_admins > 0:
        flash('Application is already set-up. Nothing to do')
        return redirect(url_for('index'))

    user_pass = UserPass()
    user_pass.get_random_user_password()

    new_admin = Users(name=user_pass.user, email='noone@nowhere.no',
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

        is_user_name_unique = (Users.query.filter(
            Users.name == user['user_name']).count() == 0)
        is_user_email_unique = (Users.query.filter(
            Users.name == user['email']).count() == 0)

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

            new_user = Users(name=user['user_name'], email=user['email'], password=password_hash,
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

    movies = Movies.query.all()

    movies_with_showtimes = defaultdict(list)
    for movie in movies:
        for showtime in movie.showtimes:
            movies_with_showtimes[movie].append({
                'start_time': showtime.start_time,
                'end_time': showtime.end_time,
                'type': showtime.type,
                'language': showtime.language
            })

    return render_template('repertoire.html', active_menu='repertoire', login=login, movies_with_showtimes=movies_with_showtimes)


@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()

    if not login.is_valid or not login.is_admin:
        flash("You don't have access to change that")
        return redirect(url_for('users'))

    if action == 'active':
        user = Users.query.filter(
            Users.name == user_name, Users.name != login.user).first()
        if user:
            user.is_active = (user.is_active + 1) % 2
            db.session.commit()
    elif action == 'admin':
        user = Users.query.filter(
            Users.name == user_name, Users.name != login.user).first()
        if user:
            user.is_admin = (user.is_admin + 1) % 2
            db.session.commit()

    return redirect(url_for('users'))


@app.route('/users')
def users():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You don't have an access to go to this page")
        return redirect(url_for('login'))

    users = Users.query.all()

    return render_template('users.html', active_menu='users', users=users, login=login)


@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid and not login.is_admin:
        flash("You are not allowed to do this. You have to be logged as an administrator")
        return redirect(url_for('users'))

    user = Users.query.filter(Users.name == user_name).first()
    message = None

    if user == None:
        flash('No such user')
        return redirect(url_for('users'))

    if request.method == 'GET':
        return render_template('edit_user.html', active_menu='users', user=user, login=login)
    else:
        new_email = '' if 'email' not in request.form else request.form['email']
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

        if new_email != user.email:
            user.email = new_email
            db.session.commit()
            flash('Email was changed')

        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            user.password = user_pass.hash_password()
            db.session.commit()
            flash('Password was changed')

        return redirect(url_for('users'))


@app.route('/delete_user/<user_name>')
def delete_user(user_name):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You have to be logged as administrator to delete users")
        return redirect(url_for('users'))

    user = Users.query.filter(Users.name == user_name,
                              Users.name != login.user).first()
    if user:
        flash('User {} has been removed'.format(user_name))

    return redirect(url_for('users'))


@app.route('/movie_base')
def movie_base():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You don't have an access to go to this page")
        return redirect(url_for('login'))

    movies = Movies.query.all()

    return render_template('movie_base.html', active_menu='movie_base', movies=movies, login=login)


@app.route('/edit_movie/<movie_title>', methods=['GET', 'POST'])
def edit_movie(movie_title):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid and not login.is_admin:
        flash("You are not allowed to do this. You have to be logged as an administrator")
        return redirect(url_for('movie_base'))

    movie = Movies.query.filter(Movies.title == movie_title).first()
    message = None

    if movie == None:
        flash('No such movie')
        return redirect(url_for('movie_base'))

    if request.method == 'GET':
        return render_template('edit_movie.html', active_menu='edit_movie', movie=movie, login=login)
    else:
        new_title = '' if 'title' not in request.form else request.form['title']
        new_duration = None if 'duration' not in request.form else request.form['duration']
        new_director = '' if 'director' not in request.form else request.form['director']
        new_description = '' if 'description' not in request.form else request.form[
            'description']
        new_photo = '' if 'photo' not in request.form else request.form['photo']

        if new_title != movie.title and new_title != '':
            movie.title = new_title
            db.session.commit()
            flash('Title was changed')

        if new_duration != None and new_duration != movie.duration:
            movie.duration = new_duration
            db.session.commit()
            flash('Duration was changed')

        if new_director != '' and new_director != movie.director:
            movie.director = new_director
            db.session.commit()
            flash('Director was changed')

        if new_description != '' and new_description != movie.description:
            movie.description = new_description
            db.session.commit()
            flash('Description was changed')

        if new_photo != '' and new_photo != movie.photo:
            movie.photo = new_photo
            db.session.commit()
            flash('Photo was changed')

        return redirect(url_for('movie_base'))


@app.route('/delete_movie/<movie_title>')
def delete_movie(movie_title):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You have to be logged as administrator to delete movies")
        return redirect(url_for('movie_base'))

    movie = Movies.query.filter(Movies.title == movie_title).first()
    if movie:
        flash('Movie {} has been removed'.format(movie_title))

    return redirect(url_for('movie_base'))


@app.route('/add_new_movie', methods=['GET', 'POST'])
def add_new_movie():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()

    message = None
    movie = {}
    if request.method == 'GET':
        return render_template('add_new_movie.html', active_menu='add_new_movie', movie=movie, login=login)
    else:
        movie['title'] = '' if 'title' not in request.form else request.form['title']
        movie['duration'] = None if 'duration' not in request.form else request.form['duration']
        movie['director'] = '' if 'director' not in request.form else request.form['director']
        movie['description'] = '' if 'description' not in request.form else request.form['description']
        print('description: ', movie['description'])
        movie['photo'] = '' if 'photo' not in request.form else request.form['photo']

        is_title_unique = (Movies.query.filter(
            Movies.title == movie['title']).count() == 0)

        is_photo_unique = (Movies.query.filter(
            Movies.photo == movie['photo']).count() == 0)

        if movie['title'] == '':
            message = 'Title cannot be empty'
        elif movie['duration'] == None:
            message = 'Duration cannot be empty'
        elif movie['director'] == '':
            message = 'Director cannot be empty'
        elif movie['description'] == '':
            message = 'Description cannot be empty'
        elif movie['photo'] == '':
            message = 'Photo cannot be empty'
        elif not is_title_unique:
            message = 'Movie with title {} already exists'.format(
                movie['title'])
        elif not is_photo_unique:
            message = 'This photo is used by another movie'

        if not message:
            new_movie = Movies(title=movie['title'], duration=movie['duration'], director=movie['director'],
                               # type: ignore
                               description=movie['description'], photo=movie['photo'])
            db.session.add(new_movie)
            db.session.commit()

            flash('Movie {} created'.format(movie['title']))
            return redirect(url_for('movie_base'))
        else:
            flash('Error: {}'.format(message))
            return render_template('add_new_movie.html', active_menu='add_new_movie', movie=movie, login=login)


if __name__ == '__main__':
    app.run()
