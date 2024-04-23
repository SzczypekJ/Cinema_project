from flask import Flask, redirect, render_template, url_for, request, flash, g, session
import mysql.connector
import os
import string
import hashlib
import binascii
import random

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SomethingWhatNoOneWillGuess'

# Admin pass:
# user name: onp
# user pass: kMw

# Dane do połączenia z bazą danych
host = 'mysql.agh.edu.pl'
port = 3306
user = 'szczype2'
password = 'Zpgbtj4kCY2kZikD'
database = 'szczype2'

# Funkcja do nawiązywania połączenia z bazą danych


def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        print("Połączono z bazą danych MySQL")
    return g.db

# Funkcja do zamykania połączenia z bazą danych


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()
        print("Zamknięto połączenie z bazą danych MySQL")


class UserPass:
    def __init__(self, user='', password=''):
        self.user = user
        self.password = password

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
        db = get_db()
        sql_statement = 'SELECT * FROM users WHERE name=%s'
        cur = db.cursor(dictionary=True)
        cur.execute(sql_statement, (self.user,))
        user_record = cur.fetchone()

        if user_record is not None and self.verify_password(user_record['password'], self.password):
            session['user'] = user_record['name']
            if user_record['is_admin']:
                session['is_admin'] = True
            return user_record
        else:
            self.user = None
            self.password = None
            return None


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'GET':
        return render_template('login.html', active_menu='login')
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
            return render_template('login.html')


@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user', None)
        flash('You are logged out')
    return redirect(url_for('login'))


@app.route('/init_app')
def init_app():
    db = get_db()
    cursor = db.cursor()
    sql_statement = 'SELECT COUNT(*) as cnt FROM users WHERE is_active and is_admin;'
    cursor.execute(sql_statement)
    active_admins = cursor.fetchone()

    if active_admins is not None and active_admins[0] > 0:
        flash('Application is already set-up. Nothing to do')
        return redirect(url_for('index'))

    user_pass = UserPass()
    user_pass.get_random_user_password()
    sql_statement = '''INSERT INTO users(name, email, password, is_active, is_admin)
                    values(%s,%s,%s,True,True);'''

    cursor.execute(sql_statement, [
        user_pass.user, 'noone@nowhere.no', user_pass.hash_password()])
    db.commit()
    flash('User {} with password {} has been created'.format(
        user_pass.user, user_pass.password))
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('index.html', active_menu='index')


@app.route('/register', methods=['GET', 'POST'])
def register():
    db = get_db()
    message = None
    user = {}
    if request.method == 'GET':
        return render_template('register.html', active_menu='register', user=user)
    else:
        user['user_name'] = '' if 'user_name' not in request.form else request.form['user_name']
        user['email'] = '' if 'email' not in request.form else request.form['email']
        user['user_pass'] = '' if 'user_pass' not in request.form else request.form['user_pass']

        cursor = db.cursor()
        cursor.execute(
            'SELECT COUNT(*) as cnt FROM users WHERE name = %s', [user['user_name']])
        record = cursor.fetchone()
        is_user_name_unique = (record['cnt'] == 0)

        cursor.execute(
            'SELECT COUNT(*) as cnt FROM users WHERE email = %s', [user['email']])
        record = cursor.fetchone()
        is_user_email_unique = (record['cnt'] == 0)

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
            sql_statement = '''INSERT INTO users(name, email, password, is_active, is_admin)
                                values(%s, %s, %s, True, False);'''

            cursor.execute(sql_statement, [
                user['user_name'], user['email'], password_hash])
            db.commit()
            flash('User {} created'.format(user['user_name']))
            return redirect(url_for('index'))
        else:
            flash('Error: {}'.format(message))
            return render_template('register.html', active_menu='register', user=user)


@app.route('/repertoire')
def repertoire():
    return render_template('repertoire.html', active_menu='repertoire')


if __name__ == '__main__':
    app.run()
