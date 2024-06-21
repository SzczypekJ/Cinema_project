from flask import Flask, request, jsonify, redirect, url_for
from database import get_db_connection

app = Flask(__name__)
app.config.from_pyfile('config.cfg')

@app.route('/admin/movie', methods=['GET'])
def movies():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM Movies')
    data = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(data)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
