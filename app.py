import pandas as pd  # For yfinance fix
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

def lookup_ticker_from_name(name):
    # Simple search—expand with better API or database later
    # Try common German/European stocks first
    stock_map = {
        'sap se': 'SAP',
        'daimler': 'DAI.DE',
        'bmw': 'BMW.DE',
        'apple': 'AAPL',
        'microsoft': 'MSFT',
        'tesla': 'TSLA',
        'volkswagen': 'VOW.DE',
        'deutsche bank': 'DBK.DE'
    }
    # Case-insensitive search
    normalized_name = name.lower().strip()
    if normalized_name in stock_map:
        return stock_map[normalized_name]
    
    # Fallback: Use yfinance to search (basic, limited—expand later)
    try:
        # Search for ticker by name (simplified—yfinance doesn’t have direct name search, so we test common tickers)
        for ticker in ['SAP', 'DAI.DE', 'BMW.DE', 'AAPL', 'MSFT', 'TSLA', 'VOW.DE', 'DBK.DE']:
            stock = yf.Ticker(ticker)
            if stock.info.get('longName', '').lower().strip() == normalized_name:
                return ticker
        return None  # No match found
    except Exception as e:
        print(f"Error looking up ticker for {name}: {e}")
        return None

def init_db():
    conn = sqlite3.connect('divcal.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
    # Check if stocks table exists and has name column
    c.execute('PRAGMA table_info(stocks)')
    columns = [col[1] for col in c.fetchall()]
    if 'name' not in columns:
        c.execute('ALTER TABLE stocks ADD COLUMN name TEXT')
    c.execute('''CREATE TABLE IF NOT EXISTS stocks 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, ticker TEXT, shares REAL, dividend REAL)''')
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
    c.execute('SELECT id, name, ticker, shares, dividend FROM stocks WHERE user_id = ?', (current_user.id,))
    stocks = [{'id': row[0], 'name': row[1], 'ticker': row[2], 'shares': row[3], 'dividend': row[4]} for row in c.fetchall()]
    total_dividends = sum(stock['dividend'] for stock in stocks)
    conn.close()
    return render_template('index.html', stocks=stocks, total_dividends=total_dividends)

@app.route('/add', methods=['POST'])
@login_required
def add_stock():
    name = request.form.get('name', '').strip()  # New field for stock name
    ticker = request.form.get('ticker', '').upper().strip()
    shares = float(request.form['shares'])
    
    # If name is provided but ticker is empty, try to look up ticker
    if name and not ticker:
        ticker = lookup_ticker_from_name(name)  # New function
        if not ticker:
            flash('Could not find ticker for the stock name provided.')
            return redirect(url_for('index'))
    
    # If ticker is provided (or found), fetch dividends
    if ticker:
        stock = yf.Ticker(ticker)
        dividends = stock.dividends
        
        # Check if dividends is a pandas Series/DataFrame and not empty
        if isinstance(dividends, pd.Series) and not dividends.empty:
            dividend_per_share = dividends.tail(1).iloc[0]  # Get the latest dividend
        else:
            dividend_per_share = 0.50  # Fallback: 0.50 EUR if no data (adjust as needed)
        
        # Convert to Euros (assuming USD to EUR at 0.92 for now—update with API later)
        dividend_per_share = dividend_per_share * 0.92 if dividend_per_share != 0.50 else dividend_per_share
        
        total_dividend = shares * dividend_per_share
        
        # Get stock name if not provided (use yfinance to fetch)
        if not name:
            name = stock.info.get('longName', ticker)  # Use longName or fallback to ticker
        
        conn = sqlite3.connect('divcal.db')
        c = conn.cursor()
        c.execute('INSERT INTO stocks (user_id, name, ticker, shares, dividend) VALUES (?, ?, ?, ?, ?)', 
                  (current_user.id, name, ticker, shares, total_dividend))
        conn.commit()
        conn.close()
        
        return redirect(url_for('index'))
    else:
        flash('Please provide a ticker or valid stock name.')
        return redirect(url_for('index'))

@app.route('/stocks/<int:id>', methods=['POST'])
@login_required
def delete_stock(id):
    conn = sqlite3.connect('divcal.db')
    c = conn.cursor()
    c.execute('DELETE FROM stocks WHERE id = ? AND user_id = ?', (id, current_user.id))
    conn.commit()
    conn.close()
    flash('Stock deleted successfully')
    return redirect(url_for('index'))

@app.route('/stocks', methods=['GET'])
@login_required
def get_stocks():
    conn = sqlite3.connect('divcal.db')
    c = conn.cursor()
    c.execute('SELECT id, name, ticker, shares, dividend FROM stocks WHERE user_id = ?', (current_user.id,))
    stocks = [{'id': row[0], 'name': row[1], 'ticker': row[2], 'shares': row[3], 'dividend': row[4]} for row in c.fetchall()]
    total_dividends = sum(stock['dividend'] for stock in stocks)
    conn.close()
    return jsonify({'stocks': stocks, 'total_dividends': total_dividends})

@app.route('/tickers', methods=['GET'])
def get_tickers():
    # Static list of common German/European tickers (expand with yfinance later)
    tickers = ['SAP', 'DAI.DE', 'BMW.DE', 'AAPL', 'MSFT', 'TSLA', 'VOW.DE', 'DBK.DE']
    return jsonify(tickers)

@app.route('/lookup_ticker', methods=['GET'])
def lookup_ticker():
    name = request.args.get('name', '').strip()
    ticker = lookup_ticker_from_name(name)
    if ticker:
        return jsonify({'ticker': ticker})
    return jsonify({'ticker': None})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5001)  # Using 5001 from your port fix