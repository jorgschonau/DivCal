from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import yfinance as yf
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace: python3 -c "import secrets; print(secrets.token_hex(16))"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def init_db():
    conn = sqlite3.connect('divcal.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS stocks 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, ticker TEXT, shares REAL, dividend REAL)''')
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('divcal.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            login_user(User(user[0]))
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        conn = sqlite3.connect('divcal.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            c.execute('SELECT id FROM users WHERE username = ?', (username,))
            user_id = c.fetchone()[0]
            login_user(User(user_id))
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Username already taken')
        conn.close()
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = sqlite3.connect('divcal.db')
    c = conn.cursor()
    c.execute('SELECT ticker, shares, dividend FROM stocks WHERE user_id = ?', (current_user.id,))
    stocks = c.fetchall()
    total_dividends = sum(stock[2] for stock in stocks)
    conn.close()
    return render_template('index.html', stocks=stocks, total_dividends=total_dividends)

@app.route('/add', methods=['POST'])
@login_required
def add_stock():
    ticker = request.form['ticker'].upper()
    shares = float(request.form['shares'])
    
    stock = yf.Ticker(ticker)
    dividends = stock.dividends.tail(1)
    dividend_per_share = dividends.iloc[0] if not dividends.empty else 0.50
    total_dividend = shares * dividend_per_share
    
    conn = sqlite3.connect('divcal.db')
    c = conn.cursor()
    c.execute('INSERT INTO stocks (user_id, ticker, shares, dividend) VALUES (?, ?, ?, ?)', 
              (current_user.id, ticker, shares, total_dividend))
    conn.commit()
    conn.close()
    
    return redirect(url_for('index'))

@app.route('/stocks', methods=['GET'])
@login_required
def get_stocks():
    conn = sqlite3.connect('divcal.db')
    c = conn.cursor()
    c.execute('SELECT ticker, shares, dividend FROM stocks WHERE user_id = ?', (current_user.id,))
    stocks = [{'ticker': row[0], 'shares': row[1], 'dividend': row[2]} for row in c.fetchall()]
    total_dividends = sum(stock['dividend'] for stock in stocks)
    conn.close()
    return jsonify({'stocks': stocks, 'total_dividends': total_dividends})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0')