import binascii
import hashlib
import string
import random
import uuid
import time
import threading
from collections import defaultdict
from sqlalchemy import Integer, String, Date, Text, Boolean, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from datetime import date, timedelta
from flask import Flask, redirect, render_template, url_for, request, flash, g, session, Blueprint
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

admin_bp = Blueprint('admin_bp', __name__)

admin_app = Flask(__name__)

admin_app.config['SECRET_KEY'] = 'SomethingWhatNoOneWillGuess'

admin_app.config.from_pyfile('config.cfg')

Base = declarative_base()

db = SQLAlchemy(model_class=Base)
db.init_app(admin_app)

class ActiveSessions(db.Model):
    __tablename__ = 'ActiveSessions'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(Integer, db.ForeignKey('Users.id'), nullable=False)
    user = db.relationship('Users', backref=db.backref(
        'active_sessions', lazy=True))
    session_id = db.Column(String(255), nullable=False, unique=True)
    created_at = db.Column(DateTime, default=datetime.now)


class Users(db.Model):
    __tablename__ = 'Users'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    name = db.Column(String(100), nullable=False)
    email = db.Column(String(100), nullable=False, unique=True)
    password = db.Column(Text, nullable=False)
    is_active = db.Column(Boolean, default=False)
    is_admin = db.Column(Boolean, default=False)


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
    start_row = db.Column(Integer, nullable=False)
    end_row = db.Column(Integer, nullable=False)


class Seats(db.Model):
    __tablename__ = 'Seats'
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    room_section_id = db.Column(Integer, db.ForeignKey(
        'RoomSections.id'), nullable=False)
    room_section = db.relationship(
        'RoomSections', backref=db.backref('seats', lazy=True))
    row_number = db.Column(Integer, nullable=False)
    seat_number = db.Column(Integer, nullable=False)
    availability = db.Column(Boolean, default=True, nullable=False)
    showtime_id = db.Column(Integer, db.ForeignKey(
        'Showtimes.id'), nullable=False)
    showtime = db.relationship(
        'Showtimes', backref=db.backref('seats', lazy=True))


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
    showtime_id = db.Column(Integer, db.ForeignKey(
        'Showtimes.id'), nullable=False)
    showtime = db.relationship(
        'Showtimes', backref=db.backref('bookings', lazy=True))
    seat_id = db.Column(Integer, db.ForeignKey('Seats.id'), nullable=False)
    seat = db.relationship('Seats', backref=db.backref('bookings', lazy=True))
    status = db.Column(String(20))
    created_at = db.Column(DateTime, default=datetime.now)
    expiry_time = db.Column(
        DateTime, default=lambda: datetime.now() + timedelta(minutes=5))


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
                user_id=user_record.id, session_id=session['session_id']) # type: ignore
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

@admin_app.context_processor
def inject_login():
    login = UserPass(session.get('user')) # type: ignore
    login.get_user_info()
    return dict(login=login)

admin_app.context_processor(inject_login)


@admin_app.route('/init_app')
def init_app():
    db.create_all()
    active_admins = Users.query.filter(
        Users.is_active == True, Users.is_admin == True).count()

    if active_admins > 0:
        flash('Application is already set-up. Nothing to do')
        return redirect("http://127.0.0.1:8000/")

    user_pass = UserPass()
    user_pass.get_random_user_password()

    new_admin = Users(name=user_pass.user, email='noone@nowhere.no',
                      password=user_pass.hash_password(), is_active=True, is_admin=True)  # type: ignore
    db.session.add(new_admin)
    db.session.commit()

    flash('User {} with password {} has been created'.format(
        user_pass.user, user_pass.password))
    return redirect("http://127.0.0.1:8000/")


@admin_app.route('/user_status_change/<action>/<user_name>')
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


@admin_app.route('/users')
def users():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You don't have an access to go to this page")
        return redirect("http://127.0.0.1:8000/login")

    users = Users.query.all()

    return render_template('users.html', active_menu='users', users=users, login=login)


@admin_app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
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
        new_user_name = '' if 'user_name' not in request.form else request.form['user_name']
        new_email = '' if 'email' not in request.form else request.form['email']
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

        if new_user_name != user.name:
            user.name = new_user_name
            db.session.commit()
            flash('User name was changed')

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


@admin_app.route('/delete_user/<user_name>')
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

    db.session.delete(user)
    db.session.commit()

    return redirect(url_for('users'))


@admin_app.route('/movie_base')
def movie_base():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You don't have an access to go to this page")
        return redirect("http://127.0.0.1:8000/login")

    movies = Movies.query.all()

    return render_template('movie_base.html', active_menu='movie_base', movies=movies, login=login)


@admin_app.route('/edit_movie/<movie_title>', methods=['GET', 'POST'])
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


@admin_app.route('/delete_movie/<movie_title>')
def delete_movie(movie_title):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You have to be logged as administrator to delete movies")
        return redirect(url_for('movie_base'))

    movie = Movies.query.filter(Movies.title == movie_title).first()
    if movie:
        flash('Movie {} has been removed'.format(movie_title))

    db.session.delete(movie)
    db.session.commit()

    return redirect(url_for('movie_base'))


@admin_app.route('/add_new_movie', methods=['GET', 'POST'])
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


@admin_app.route('/showtime_base')
def showtime_base():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You don't have an access to go to this page")
        return redirect("http://127.0.0.1:8000/login")

    showtimes = Showtimes.query.all()

    return render_template('showtime_base.html', active_menu='showtime_base', showtimes=showtimes, login=login)


@admin_app.route('/edit_showtime/<showtime_id>', methods=['GET', 'POST'])
def edit_showtime(showtime_id):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid and not login.is_admin:
        flash("You are not allowed to do this. You have to be logged as an administrator")
        return redirect(url_for('showtime_base'))

    showtime = Showtimes.query.filter(Showtimes.id == showtime_id).first()
    message = None
    movies = Movies.query.all()
    rooms = Rooms.query.all()

    if showtime == None:
        flash('No such showtime')
        return redirect(url_for('showtime_base'))

    if request.method == 'GET':
        return render_template('edit_showtime.html', active_menu='edit_showtime', showtime=showtime, login=login, movies=movies, rooms=rooms)
    else:
        new_movie_id = None if 'movie_id' not in request.form else request.form['movie_id']
        new_room_id = None if 'room_id' not in request.form else request.form['room_id']
        new_start_time = '' if 'start_time' not in request.form else request.form[
            'start_time']
        new_end_time = '' if 'end_time' not in request.form else request.form['end_time']
        new_type = '' if 'type' not in request.form else request.form['type']
        new_language = '' if 'language' not in request.form else request.form['language']

        try:
            if new_start_time != '':
                new_start_time = datetime.strptime(
                    new_start_time, '%Y-%m-%d %H:%M:%S')
            if new_end_time != '':
                new_end_time = datetime.strptime(
                    new_end_time, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD HH:MM:SS')
            return redirect(url_for('edit_showtime', showtime_id=showtime_id))

        if new_movie_id != showtime.movie_id and new_movie_id != None:
            showtime.movie_id = new_movie_id
            db.session.commit()
            flash('Movie_id was changed')

        if new_room_id != None and new_room_id != showtime.room_id:
            showtime.room_id = new_room_id
            db.session.commit()
            flash('Room_id was changed')

        if new_start_time != '' and new_start_time != showtime.start_time:
            showtime.start_time = new_start_time
            db.session.commit()
            flash('Start_time was changed')

        if new_end_time != '' and new_end_time != showtime.end_time:
            showtime.end_time = new_end_time
            db.session.commit()
            flash('End_time was changed')

        if new_type != '' and new_type != showtime.type:
            showtime.type = new_type
            db.session.commit()
            flash('Type was changed')

        if new_language != '' and new_language != showtime.language:
            showtime.language = new_language
            db.session.commit()
            flash('Language was changed')

        Seats.query.filter_by(showtime_id=showtime_id).delete()
        db.session.commit()

        create_seats_for_showtime(showtime_id)

        return redirect(url_for('showtime_base'))


def create_seats_for_showtime(showtime_id):
    showtime = Showtimes.query.get(showtime_id)
    if not showtime:
        return

    room_sections = RoomSections.query.filter_by(
        room_id=showtime.room_id).all()
    for section in room_sections:
        for row in range(section.start_row, section.end_row + 1):
            for seat_number in range(1, section.seats_per_row + 1):
                new_seat = Seats(
                    room_section_id=section.id,
                    row_number=row,
                    seat_number=seat_number,
                    availability=True,
                    showtime_id=showtime_id
                )  # type: ignore
                db.session.add(new_seat)
    db.session.commit()


@admin_app.route('/delete_showtime/<showtime_id>')
def delete_showtime(showtime_id):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You have to be logged as administrator to delete showtime")
        return redirect(url_for('showtime_base'))

    showtime = Showtimes.query.filter(Showtimes.id == showtime_id).first()
    if showtime:
        Seats.query.filter_by(showtime_id=showtime_id).delete()
        db.session.commit()

        db.session.delete(showtime)
        db.session.commit()
        flash('Showtime {} has been removed'.format(showtime_id))
    else:
        flash('Showtime not found')

    return redirect(url_for('showtime_base'))


@admin_app.route('/add_new_showtime', methods=['GET', 'POST'])
def add_new_showtime():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()

    if not login.is_valid or not login.is_admin:
        flash("You have to be logged as administrator to add new showtime")
        return redirect(url_for('showtime_base'))

    message = None
    showtime = {}
    movies = Movies.query.all()
    rooms = Rooms.query.all()
    if request.method == 'GET':
        return render_template('add_new_showtime.html', active_menu='add_new_showtime', showtime=showtime, login=login, movies=movies, rooms=rooms)
    else:
        showtime['movie_id'] = None if 'movie_id' not in request.form else request.form['movie_id']
        showtime['room_id'] = None if 'room_id' not in request.form else request.form['room_id']
        showtime['start_time'] = '' if 'start_time' not in request.form else request.form['start_time']
        showtime['end_time'] = '' if 'end_time' not in request.form else request.form['end_time']
        showtime['type'] = '' if 'type' not in request.form else request.form['type']
        showtime['language'] = '' if 'language' not in request.form else request.form['language']

        try:
            start_time = datetime.strptime(
                showtime['start_time'], '%Y-%m-%d %H:%M:%S')
            end_time = datetime.strptime(
                showtime['end_time'], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD HH:MM:SS')
            return redirect(url_for('add_new_showtime'))

        if not Movies.query.filter_by(id=showtime['movie_id']).first():
            message = 'Movie with the given ID does not exist.'

        conflicting_showtimes = Showtimes.query.filter(
            Showtimes.room_id == showtime['room_id'],
            Showtimes.start_time < end_time,
            Showtimes.end_time > start_time
        ).all()

        if conflicting_showtimes:
            message = 'Room is not available at the specified time.'
            return redirect(url_for('add_new_showtime'))

        if showtime['movie_id'] is None:
            message = 'Movie_id cannot be empty'
        elif showtime['room_id'] is None:
            message = 'Room_id cannot be empty'
        elif showtime['start_time'] == '':
            message = 'Start_time cannot be empty'
        elif showtime['end_time'] == '':
            message = 'End_time cannot be empty'
        elif showtime['type'] == '':
            message = 'Type cannot be empty'
        elif showtime['language'] == '':
            message = 'Language cannot be empty'

        if not message:
            new_showtime = Showtimes(
                movie_id=showtime['movie_id'],
                room_id=showtime['room_id'],
                start_time=start_time,
                end_time=end_time,
                type=showtime['type'],
                language=showtime['language']
            )  # type: ignore
            db.session.add(new_showtime)
            db.session.commit()

            create_seats_for_showtime(new_showtime.id)

            flash('Showtime for movie {} and room {} created'.format(
                showtime['movie_id'], showtime['room_id']))
            return redirect(url_for('showtime_base'))
        else:
            flash('Error: {}'.format(message))
            return render_template('add_new_showtime.html', active_menu='add_new_showtime', showtime=showtime, login=login, movies=movies, rooms=rooms)


@admin_app.route('/your_account/<user_name>')
def your_account(user_name):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    user = Users.query.filter(Users.name == user_name).first()
    if not login.is_valid or not login.is_active or user is None:
        flash("You have to be logged in to see your account")
        return redirect("http://127.0.0.1:8000/login")

    bookings = Bookings.query.filter_by(user_id=user.id).all()
    return render_template("your_account.html", login=login, user=user, bookings=bookings,
                           active_menu='your_account')


@admin_app.route('/edit_your_account/<user_name>', methods=['GET', 'POST'])
def edit_your_account(user_name):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid and not login.is_active:
        flash("Your login is not valid or your account is not active")
        return redirect("http://127.0.0.1:8000/")

    user = Users.query.filter(Users.name == user_name).first()

    if user == None:
        flash('No such user')
        return redirect("http://127.0.0.1:8000/login")

    if request.method == "GET":
        return render_template("edit_your_account.html", active_menu='edit_your_account', login=login, user=user)
    else:
        new_user_name = '' if 'user_name' not in request.form else request.form['user_name']
        new_email = '' if 'email' not in request.form else request.form['email']
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

        if new_user_name != user.name:
            user.name = new_user_name
            db.session.commit()
            flash('User name was changed')

        if new_email != user.email:
            user.email = new_email
            db.session.commit()
            flash('Email was changed')

        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            user.password = user_pass.hash_password()
            db.session.commit()
            flash('Password was changed')

        return redirect("http://127.0.0.1:8002/your_account")


@admin_app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    booking = Bookings.query.get(booking_id)
    if not booking:
        flash("Booking not found")
        return redirect(url_for("http://127.0.0.1:8001/your_account/{session.get('user')}"))    

    payment = Payments.query.filter_by(booking_id=booking_id).first()
    if payment:
        db.session.delete(payment)

    seat = Seats.query.get(booking.seat_id)
    if seat:
        seat.availability = True

    db.session.delete(booking)
    db.session.commit()

    flash("Your booking has been cancelled.")
    return redirect(url_for("http://127.0.0.1:8001/your_account/{session.get('user')}"))


@admin_app.route('/room_base')
def room_base():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You don't have an access to go to this page")
        return redirect("http://127.0.0.1:8000/login")

    rooms = Rooms.query.all()

    return render_template('room_base.html', active_menu='room_base', rooms=rooms,
                           login=login)


@admin_app.route('/edit_room_base/<int:room_id>', methods=['GET', 'POST'])
def edit_room_base(room_id):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(
            "You are not allowed to do this. You have to be logged in as an administrator")
        return redirect(url_for('room_base'))

    room = Rooms.query.get(room_id)
    if room is None:
        flash('No such room')
        return redirect(url_for('room_base'))

    if request.method == 'GET':
        return render_template('edit_room_base.html', active_menu='edit_room_base', room=room, login=login)
    else:
        new_name = request.form.get('name')
        new_capacity = request.form.get('capacity')

        if new_name and new_name != room.name:
            room.name = new_name
            flash('Name was changed')

        if new_capacity and new_capacity != room.capacity:
            room.capacity = new_capacity
            flash('Capacity was changed')

        db.session.commit()
        return redirect(url_for('room_base'))


@admin_app.route('/delete_room/<room_id>')
def delete_room(room_id):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You have to be logged as administrator to delete room")
        return redirect(url_for('room_base'))

    room = Rooms.query.filter(Rooms.id == room_id).first()
    if room:
        flash('Room {} has been removed'.format(room_id))

    db.session.delete(room)
    db.session.commit()
    return redirect(url_for('room_base'))


@admin_app.route('/add_new_room', methods=['GET', 'POST'])
def add_new_room():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()

    if not login.is_valid or not login.is_admin:
        flash(
            "You are not allowed to do this. You have to be logged in as an administrator")
        return redirect(url_for('room_base'))

    message = None
    room = {}
    if request.method == 'GET':
        return render_template('add_new_room.html', active_menu='add_new_room', room=room, login=login)
    else:
        room['name'] = None if 'name' not in request.form else request.form['name']
        room['capacity'] = '' if 'capacity' not in request.form else request.form['capacity']

        if room['name'] == '':
            message = 'Name cannot be empty'
        elif room['capacity'] == None:
            message = 'Capacity cannot be empty'

        if not message:
            new_room = Rooms(name=room['name'],
                             capacity=room['capacity'])  # type: ignore
            db.session.add(new_room)
            db.session.commit()
            flash('Room added successfully')
            return redirect(url_for('room_base'))
        else:
            flash('Error: {}'.format(message))
            return render_template('add_new_room.html', active_menu='add_new_room', room=room, login=login)


@admin_app.route('/room_section_base')
def room_section_base():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You don't have an access to go to this page")
        return redirect("http://127.0.0.1:8000/login")

    room_sections = RoomSections.query.all()

    return render_template('room_section_base.html', active_menu='room_section_base', room_sections=room_sections,
                           login=login)


@admin_app.route('/edit_room_section/<room_section_id>', methods=['GET', 'POST'])
def edit_room_section(room_section_id):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid and not login.is_admin:
        flash("You are not allowed to do this. You have to be logged as an administrator")
        return redirect(url_for('room_section_base'))

    room_section = RoomSections.query.filter(
        RoomSections.id == room_section_id).first()

    if room_section == None:
        flash('No such room section')
        return redirect(url_for('room_section_base'))

    if request.method == 'GET':
        return render_template('edit_room_section.html', active_menu='edit_room_section', room_section=room_section,
                               login=login)
    else:
        new_room_id = None if 'room_id' not in request.form else request.form['room_id']
        new_section_type = '' if 'section_type' not in request.form else request.form[
            'section_type']
        new_capacity = None if 'capacity' not in request.form else request.form['capacity']
        new_num_rows = None if 'num_rows' not in request.form else request.form['num_rows']
        new_seats_per_row = None if 'seats_per_row' not in request.form else request.form[
            'seats_per_row']
        new_price_multiplier = None if 'price_multiplier' not in request.form else request.form[
            'price_multiplier']
        new_start_row = None if 'start_row' not in request.form else request.form['start_row']
        new_end_row = None if 'end_row' not in request.form else request.form['end_row']

        existing_sections = RoomSections.query.filter_by(
            room_id=new_room_id).all()
        for existing_section in existing_sections:
            if (new_start_row is not None and new_end_row is not None and
                int(new_start_row) <= int(existing_section.end_row) and
                int(new_end_row) >= int(existing_section.start_row) and
                    existing_section.id != room_section.id):
                flash('New section overlaps with existing section')
                return render_template('edit_room_section.html', active_menu='edit_room_section', room_section=room_section,
                                       login=login)

        message = check_room_capacity_edit(room_section)
        if message:
            flash('Error: {}'.format(message))
            return render_template('edit_room_section.html', active_menu='edit_room_section', room_section=room_section,
                                   login=login)

        if new_room_id != None and new_room_id != room_section.room_id:
            room_section.room_id = new_room_id
            db.session.commit()
            flash('Room_id was changed')

        if new_section_type != '' and new_section_type != room_section.section_type:
            room_section.section_type = new_section_type
            db.session.commit()
            flash('Section_type was changed')

        if new_capacity != None and new_capacity != room_section.capacity:
            room_section.capacity = new_capacity
            db.session.commit()
            flash('Capacity was changed')

        if new_num_rows != None and new_num_rows != room_section.num_rows:
            room_section.num_rows = new_num_rows
            db.session.commit()
            flash('Num_rows was changed')

        if new_seats_per_row != None and new_seats_per_row != room_section.seats_per_row:
            room_section.seats_per_row = new_seats_per_row
            db.session.commit()
            flash('Seats_per_row was changed')

        if new_price_multiplier != None and new_price_multiplier != room_section.price_multiplier:
            room_section.price_multiplier = new_price_multiplier
            db.session.commit()
            flash('Price_multiplier was changed')

        if new_start_row != None and new_start_row != room_section.start_row:
            room_section.start_row = new_start_row
            db.session.commit()
            flash('Start_row was changed')

        if new_end_row != None and new_end_row != room_section.end_row:
            room_section.end_row = new_end_row
            db.session.commit()
            flash('End_row was changed')

        showtimes = Showtimes.query.filter_by(
            room_id=room_section.room_id).all()
        for showtime in showtimes:
            create_seats_for_showtime(showtime.id)

        return redirect(url_for('room_section_base'))


def check_room_capacity_edit(room_section):
    room_id = room_section.room_id
    room_capacity = Rooms.query.filter_by(
        id=room_id).first().capacity  # type: ignore
    new_section_capacity = int(room_section.num_rows) * \
        int(room_section.seats_per_row)
    if new_section_capacity > room_capacity:
        return 'New section capacity exceeds room capacity'
    else:
        return None


@admin_app.route('/delete_room_section/<room_section_id>')
def delete_room_section(room_section_id):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You have to be logged as administrator to delete room_section")
        return redirect(url_for('room_section_base'))

    room_section = RoomSections.query.filter(
        RoomSections.id == room_section_id).first()
    if room_section:
        flash('Showtime {} has been removed'.format(room_section_id))

    db.session.delete(room_section)
    db.session.commit()
    return redirect(url_for('room_section_base'))


@admin_app.route('/add_new_room_section', methods=['GET', 'POST'])
def add_new_room_section():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash("You have to be logged as administrator to add new room_section")
        return redirect(url_for('room_section_base'))

    message = None
    room_section = {}
    if request.method == 'GET':
        return render_template('add_new_room_section.html', active_menu='add_new_room_section',
                               room_section=room_section, login=login)
    else:
        room_section['room_id'] = None if 'room_id' not in request.form else request.form['room_id']
        room_section['section_type'] = '' if 'section_type' not in request.form else request.form['section_type']
        room_section['capacity'] = None if 'capacity' not in request.form else request.form['capacity']
        room_section['num_rows'] = None if 'num_rows' not in request.form else request.form['num_rows']
        room_section['seats_per_row'] = None if 'seats_per_row' not in request.form else request.form['seats_per_row']
        room_section['price_multiplier'] = None if 'price_multiplier' not in request.form else request.form['price_multiplier']
        room_section['start_row'] = None if 'start_row' not in request.form else request.form['start_row']
        room_section['end_row'] = None if 'end_row' not in request.form else request.form['end_row']

        message = check_room_capacity(room_section)
        if message:
            flash('Error: {}'.format(message))
            return render_template('add_new_room_section.html', active_menu='add_new_room_section',
                                   room_section=room_section, login=login)

        if not Rooms.query.filter_by(id=room_section['room_id']).first():
            message = 'Room with the given ID does not exist.'

        if room_section['room_id'] == None:
            message = 'Room_id cannot be empty'
        elif room_section['section_type'] == '':
            message = 'Section_type cannot be empty'
        elif room_section['capacity'] == None:
            message = 'Capacity cannot be empty'
        elif room_section['num_rows'] == None:
            message = 'Num_rows cannot be empty'
        elif room_section['seats_per_row'] == None:
            message = 'Seats_per_row cannot be empty'
        elif room_section['price_multiplier'] == None:
            message = 'Price_multiplier cannot be empty'
        elif room_section['start_row'] == None:
            message = 'Start_row cannot be empty'
        elif room_section['end_row'] == None:
            message = 'End_row cannot be empty'
        elif int(room_section['seats_per_row']) * int(room_section['num_rows']) > int(room_section['capacity']):  # type: ignore
            message = 'Section capacity exceeds room capacity'
        else:
            existing_sections = RoomSections.query.filter_by(
                room_id=room_section['room_id']).all()
            for existing_section in existing_sections:
                if (int(room_section['start_row']) <= int(existing_section.end_row) and
                        int(room_section['end_row']) >= int(existing_section.start_row)):
                    message = 'New section overlaps with existing section'
                    break
        if not message:
            new_room_section = RoomSections(room_id=room_section['room_id'], section_type=room_section['section_type'],
                                            capacity=room_section['capacity'],
                                            num_rows=room_section['num_rows'], seats_per_row=room_section['seats_per_row'],
                                            price_multiplier=room_section['price_multiplier'],
                                            start_row=room_section['start_row'],
                                            # type: ignore
                                            end_row=room_section['end_row'])
            db.session.add(new_room_section)
            db.session.commit()
            flash('Room_section for room {} was created'.format(
                room_section['room_id']))
            return redirect(url_for('room_section_base'))
        else:
            flash('Error: {}'.format(message))
            return render_template('add_new_room_section.html', active_menu='add_new_room_section',
                                   room_section=room_section, login=login)


def check_room_capacity(room_section):
    room_id = room_section['room_id']
    room = Rooms.query.filter_by(id=room_id).first()
    if room is None:
        return 'Room with the given ID does not exist.'

    room_capacity = room.capacity
    new_section_capacity = int(
        room_section['num_rows']) * int(room_section['seats_per_row'])
    if new_section_capacity > room_capacity:
        return 'New section capacity exceeds room capacity'
    else:
        return None


@admin_app.route('/bookings/<int:user_id>/<int:showtime_id>', methods=['GET', 'POST'])
def bookings(user_id, showtime_id):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_active:
        flash("You have to be logged in to book tickets")
        return redirect("http://127.0.0.1:8000/login")

    current_user = Users.query.get(user_id)
    if not current_user:
        flash("User not found")
        return redirect("http://127.0.0.1:8000/")

    showtime = Showtimes.query.get(showtime_id)
    if not showtime:
        flash("Showtime not found")
        return redirect("http://127.0.0.1:8002/repertoire")

    if request.method == 'POST':
        seat_id = request.form['seat']
        status = request.form['status']

        seat = Seats.query.filter_by(
            id=seat_id, showtime_id=showtime_id).first()
        if not seat or not seat.availability:
            flash("Selected seat is no longer available. Please choose another seat.")
            return redirect(f"http://127.0.0.1:8001/bookings/{user_id}/{showtime_id}")
        

        booking_id = save_booking(user_id, showtime_id, seat_id, status)
        flash("Booking successful!")
        return redirect(url_for('payment', booking_id=booking_id))

    seats = db.session.query(Seats).filter_by(showtime_id=showtime_id).all()
    room_sections = RoomSections.query.filter_by(
        room_id=showtime.room_id).all()

    return render_template('bookings.html', active_menu='bookings', login=login,
                           user=current_user, showtime=showtime,
                           seats=seats, room_sections=room_sections)


def save_booking(user_id, showtime_id, seat_id, status):
    new_booking = Bookings(
        user_id=user_id, showtime_id=showtime_id, seat_id=seat_id, status=status,
        expiry_time=datetime.now() + timedelta(minutes=5)
    )  # type: ignore
    db.session.add(new_booking)

    seat = Seats.query.filter_by(id=seat_id, showtime_id=showtime_id).first()
    if seat:
        seat.availability = False

    db.session.commit()
    return new_booking.id


@admin_app.route('/payment/<int:booking_id>')
def payment(booking_id):
    booking = Bookings.query.get(booking_id)
    if not booking:
        flash("Booking not found")
        return redirect("http://127.0.0.1:8000/")

    user = Users.query.get(booking.user_id)
    if not user:
        flash("User not found")
        return redirect("http://127.0.0.1:8000/login")

    return render_template('payment.html', booking=booking, user=user)


@admin_app.route('/process_payment/<int:booking_id>', methods=['POST'])
def process_payment(booking_id):
    booking = Bookings.query.get(booking_id)
    if not booking:
        flash("Booking not found")
        return redirect("http://127.0.0.1:8000/")

    payment_method = request.form.get('payment_method')
    if not payment_method:
        flash("Payment method not specified")
        return redirect(url_for('payment', booking_id=booking_id))

    new_payment = Payments(
        booking_id=booking_id,
        amount=calculate_amount(booking),
        status="Completed",
        payment_method=payment_method,
        transaction_id=generate_transaction_id()
    )  # type: ignore
    db.session.add(new_payment)

    booking.status = 'Purchased'
    db.session.commit()

    flash("Payment successful!")
    return redirect("http://127.0.0.1:8000/")


def calculate_amount(booking):
    base_price = 20.0
    seat = Seats.query.get(booking.seat_id)
    if not seat:
        return base_price

    room_section = RoomSections.query.get(seat.room_section_id)
    if not room_section:
        return base_price

    final_price = base_price * room_section.price_multiplier
    return final_price


def generate_transaction_id():
    return str(uuid.uuid4())

admin_app.register_blueprint(admin_bp, url_prefix='/admin')

if __name__ == '__main__':
    admin_app.run(host='0.0.0.0', port=8001)
