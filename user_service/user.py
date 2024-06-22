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

user_bp = Blueprint('user', __name__)

user_app = Flask(__name__)

user_app.config['SECRET_KEY'] = 'SomethingWhatNoOneWillGuess'

user_app.config.from_pyfile('config.cfg')

Base = declarative_base()

db = SQLAlchemy(model_class=Base)
db.init_app(user_app)

user_app.register_blueprint(user_bp)

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

@user_app.context_processor
def inject_login():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    return dict(login=login)

user_app.context_processor(inject_login)

@user_app.route('/repertoire')
def repertoire():
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()

    movies = Movies.query.all()
    user_id = login.id if login.is_valid else None

    movies_with_showtimes = defaultdict(list)
    for movie in movies:
        for showtime in movie.showtimes:
            movies_with_showtimes[movie].append({
                'id': showtime.id,
                'start_time': showtime.start_time,
                'end_time': showtime.end_time,
                'type': showtime.type,
                'language': showtime.language
            })

    return render_template('repertoire.html', active_menu='repertoire', login=login,
                           movies_with_showtimes=movies_with_showtimes, user_id=user_id)


@user_app.route('/your_account/<user_name>')
def your_account(user_name):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    user = Users.query.filter(Users.name == user_name).first()
    if not login.is_valid or not login.is_active or user is None:
        flash("You have to be logged in to see your account")
        return redirect(url_for('auth.login'))

    bookings = Bookings.query.filter_by(user_id=user.id).all()
    return render_template("your_account.html", login=login, user=user, bookings=bookings,
                           active_menu='your_account')


@user_app.route('/edit_your_account/<user_name>', methods=['GET', 'POST'])
def edit_your_account(user_name):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid and not login.is_active:
        flash("Your login is not valid or your account is not active")
        return redirect(url_for('auth.index'))

    user = Users.query.filter(Users.name == user_name).first()

    if user == None:
        flash('No such user')
        return redirect(url_for('auth.login'))

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

        return redirect(url_for('your_account'))


@user_app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    booking = Bookings.query.get(booking_id)
    if not booking:
        flash("Booking not found")
        return redirect(url_for('your_account', user_name=session.get('user')))

    payment = Payments.query.filter_by(booking_id=booking_id).first()
    if payment:
        db.session.delete(payment)

    seat = Seats.query.get(booking.seat_id)
    if seat:
        seat.availability = True

    db.session.delete(booking)
    db.session.commit()

    flash("Your booking has been cancelled.")
    return redirect(url_for('your_account', user_name=session.get('user')))


@user_app.route('/bookings/<int:user_id>/<int:showtime_id>', methods=['GET', 'POST'])
def bookings(user_id, showtime_id):
    login = UserPass(session.get('user'))  # type: ignore
    login.get_user_info()
    if not login.is_valid or not login.is_active:
        flash("You have to be logged in to book tickets")
        return redirect(url_for('auth.login'))

    current_user = Users.query.get(user_id)
    if not current_user:
        flash("User not found")
        return redirect(url_for('auth.index'))

    showtime = Showtimes.query.get(showtime_id)
    if not showtime:
        flash("Showtime not found")
        return redirect(url_for('repertoire'))

    if request.method == 'POST':
        seat_id = request.form['seat']
        status = request.form['status']

        seat = Seats.query.filter_by(
            id=seat_id, showtime_id=showtime_id).first()
        if not seat or not seat.availability:
            flash("Selected seat is no longer available. Please choose another seat.")
            return redirect(url_for('bookings', user_id=user_id, showtime_id=showtime_id))

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


@user_app.route('/payment/<int:booking_id>')
def payment(booking_id):
    booking = Bookings.query.get(booking_id)
    if not booking:
        flash("Booking not found")
        return redirect(url_for('auth.index'))

    user = Users.query.get(booking.user_id)
    if not user:
        flash("User not found")
        return redirect(url_for('auth.index'))

    return render_template('payment.html', booking=booking, user=user)


@user_app.route('/process_payment/<int:booking_id>', methods=['POST'])
def process_payment(booking_id):
    booking = Bookings.query.get(booking_id)
    if not booking:
        flash("Booking not found")
        return redirect(url_for('auth.index'))

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
    return redirect(url_for('auth.index'))


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


if __name__ == '__main__':
    user_app.run(host='0.0.0.0', port=8003)