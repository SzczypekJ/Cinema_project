from flask import Flask, redirect, render_template, url_for, request, flash, g, session, Blueprint
from sqlalchemy import Integer, String, Date, Text, Boolean, Float, DateTime
import binascii
import hashlib
import string
import random
import uuid
import time
import threading
from collections import defaultdict
from sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, timedelta
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

auth_app = Flask(__name__)

auth_app.config['SECRET_KEY'] = 'SomethingWhatNoOneWillGuess'
auth_app.config.from_pyfile('config.cfg')

Base = declarative_base()

db = SQLAlchemy(model_class=Base)
db.init_app(auth_app)

# Blueprint for authentication routes in our app
auth_bp = Blueprint('auth_bp', __name__)

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



@auth_app.context_processor
def inject_login():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    return dict(login=login)


auth_app.context_processor(inject_login)
# Admin pass:
# user name: dhg
# user pass: hYk



def release_expired_bookings():
    while True:
        with auth_app.app_context():
            print("Checking for expired bookings...")
            expired_bookings = Bookings.query.filter(
                Bookings.expiry_time < datetime.now(),
                Bookings.status != 'Purchased'
            ).all()
            for booking in expired_bookings:
                print(f"Releasing seat for booking ID: {booking.id}")
                seat = Seats.query.get(booking.seat_id)
                if seat:
                    seat.availability = True
                db.session.delete(booking)
            db.session.commit()
        time.sleep(60)


@auth_bp.route('/login', methods=['GET', 'POST'])
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


@auth_bp.route('/logout')
def logout():
    if 'user' in session:
        user_record = Users.query.filter(Users.name == session['user']).first()
        if user_record:
            ActiveSessions.query.filter_by(
                user_id=user_record.id, session_id=session['session_id']).delete()

            user_record.is_active = False
            db.session.commit()

        session.clear()
        flash('You are logged out')
    return redirect(url_for('auth_bp.login'))


@auth_bp.route('/init_app')
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


@auth_app.route('/')
def index():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    return render_template('index.html', active_menu='home', login=login)


@auth_app.route('/register', methods=['GET', 'POST'])
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
            return redirect(url_for('auth_bp.login'))
        else:
            flash('Error: {}'.format(message))
            return render_template('register.html', active_menu='register', user=user, login=login)


auth_app.register_blueprint(auth_bp)

if __name__ == '__main__':
    release_thread = threading.Thread(target=release_expired_bookings)
    release_thread.start()
    auth_app.run(host='0.0.0.0', port=8000)
