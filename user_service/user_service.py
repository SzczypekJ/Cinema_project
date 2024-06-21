from flask import Flask, request, jsonify
from database import get_db_connection

app = Flask(__name__)
app.config.from_pyfile('config.cfg')

@app.route('/user/book', methods=['POST'])
def book_ticket():
    data = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO Bookings (user_id, showtime_id, seat_id) VALUES (?, ?, ?)', 
                (data['user_id'], data['showtime_id'], data['seat_id']))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'status': 'success'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
