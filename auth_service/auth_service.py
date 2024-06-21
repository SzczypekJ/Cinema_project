from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
from database_connection import db, get_db_connection

app = Flask(__name__)
app.config.from_pyfile('../config.cfg')

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
