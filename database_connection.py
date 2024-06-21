from flask import Flask, redirect, render_template, url_for, request, flash, g, session
from datetime import date, timedelta
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Integer, String, Date, Text, Boolean, Float, DateTime


app = Flask(__name__)

app.config['SECRET_KEY'] = 'SomethingWhatNoOneWillGuess'

app.config.from_pyfile('config.cfg')

Base = declarative_base()

db = SQLAlchemy(model_class=Base)
db.init_app(app)


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
    