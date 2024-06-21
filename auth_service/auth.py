from token_utils import UserPass, inject_login
from token_utils import *
from flask import Flask, redirect, render_template, url_for, request, flash, g, session, Blueprint
from database_connection import get_db_connection, ActiveSessions, Users, Movies, Rooms, RoomSections, Seats, Showtimes, Bookings, RoomBookings, Payments
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
from werkzeug.security import check_password_hash
from flask import Flask, request, jsonify


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SomethingWhatNoOneWillGuess'
app.config.from_pyfile('config.cfg')

Base = declarative_base()

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Blueprint for authentication routes in our app
auth_bp = Blueprint('auth_bp', __name__)


app.context_processor(inject_login)
# Admin pass:
# user name: dhg
# user pass: hYk


def release_expired_bookings():
    while True:
        with app.app_context():
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

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM Users WHERE email = ?', (data['email'],))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if user and check_password_hash(user['password'], data['password']):
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failed'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)


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
            return redirect(url_for('auth_bp.login'))
        else:
            flash('Error: {}'.format(message))
            return render_template('register.html', active_menu='register', user=user, login=login)


app.register_blueprint(auth_bp)

if __name__ == '__main__':
    release_thread = threading.Thread(target=release_expired_bookings)
    release_thread.start()
    app.run(host='0.0.0.0', port=8000)
