from token_utils import UserPass, inject_login
from database_connection import *
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
from token_utils import *
from auth_service.auth import auth_bp

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

user_bp = Blueprint('user', __name__)


app.context_processor(inject_login)

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SomethingWhatNoOneWillGuess'

app.config.from_pyfile('config.cfg')

Base = declarative_base()

db = SQLAlchemy(model_class=Base)
db.init_app(app)

app.register_blueprint(auth_bp)


@app.route('/repertoire')
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


@app.route('/your_account/<user_name>')
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


@app.route('/edit_your_account/<user_name>', methods=['GET', 'POST'])
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


@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
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


@app.route('/bookings/<int:user_id>/<int:showtime_id>', methods=['GET', 'POST'])
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


@app.route('/payment/<int:booking_id>')
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


@app.route('/process_payment/<int:booking_id>', methods=['POST'])
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
