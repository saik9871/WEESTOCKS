from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import math
import os
from dotenv import load_dotenv
import requests
from urllib.parse import urlencode
from requests_oauthlib import OAuth2Session
import secrets
import random
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from sqlalchemy import exc, inspect, text, create_engine
from sqlalchemy.pool import QueuePool

# Load environment variables
load_dotenv()

# Debug print to verify database URL
print("Using database URL:", os.getenv('DATABASE_URL', 'No DATABASE_URL found in environment'))

app = Flask(__name__)

# Enhanced session security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)

# Enhanced database configuration
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 20,  # Increased from 10
    'max_overflow': 30,  # Allow up to 30 additional connections
    'pool_recycle': 1800,  # Recycle connections after 30 minutes
    'pool_pre_ping': True,  # Check connection validity before using
    'pool_timeout': 30,  # Wait up to 30 seconds for available connection
    'poolclass': QueuePool
}

# Use DATABASE_URL from environment variables, fallback to SQLite for local development
database_url = os.getenv('DATABASE_URL', 'postgresql://neondb_owner:npg_G9shViASrx8J@ep-late-unit-a80vzjan-pooler.eastus2.azure.neon.tech/neondb?sslmode=require')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

print("Connecting to database:", database_url)  # Debug print to verify connection string

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Twitch OAuth Configuration
TWITCH_CLIENT_ID = 'shdewm91zxskpkg12fi3hphsfsajlc'
TWITCH_CLIENT_SECRET = 'q4kuhmknmf7i56mxwz4tfkkad18av3'
TWITCH_REDIRECT_URI = 'https://weenstock.up.railway.app/auth/twitch/callback'  # Updated to production URL

# Create engine with optimized settings
engine = create_engine(
    database_url,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=30,
    pool_recycle=1800,
    pool_pre_ping=True,
    pool_timeout=30
)

db = SQLAlchemy(app)
db.engine = engine

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    twitch_id = db.Column(db.String(50), unique=True, nullable=True)
    twitch_login = db.Column(db.String(80), unique=True, nullable=True)
    twitch_email = db.Column(db.String(120), unique=True, nullable=True)
    twitch_profile_image = db.Column(db.String(255), nullable=True)
    cash = db.Column(db.Float, nullable=False, default=500.0)
    is_admin = db.Column(db.Boolean, default=False)
    can_add_stocks = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=True)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_authenticated(self):
        return True if self.twitch_id else False

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    total_shares = db.Column(db.Integer, nullable=False)
    shares_held = db.Column(db.Integer, nullable=False)
    previous_close = db.Column(db.Float, nullable=False, default=0.0)
    initial_price = db.Column(db.Float, nullable=False)
    last_viewed = db.Column(db.DateTime, nullable=True)
    view_count = db.Column(db.Integer, default=0)
    trade_count = db.Column(db.Integer, default=0)

    def calculate_interest_score(self):
        """
        Calculate interest score using an exponential decay function for time
        and logarithmic scaling for counts to prevent extreme values.
        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        current_time = datetime.utcnow()
        
        # Time decay factor (exponential decay)
        if self.last_viewed:
            hours_since_view = (current_time - self.last_viewed).total_seconds() / 3600
            time_factor = math.exp(-0.1 * hours_since_view)  # Decay by ~10% per hour
        else:
            time_factor = 0.1  # Base factor for never-viewed stocks
        
        # Logarithmic scaling for view and trade counts to prevent extreme values
        view_factor = math.log(self.view_count + 1, 2)  # log base 2
        trade_factor = math.log(self.trade_count + 1, 2)
        
        # Weighted combination (40% views, 60% trades)
        return (0.4 * view_factor + 0.6 * trade_factor) * time_factor

class Position(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    shares = db.Column(db.Integer, nullable=False, default=0)

class StockHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    price_change = db.Column(db.Float, nullable=False)  # Percentage change
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    volume = db.Column(db.Integer, nullable=False)

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ends_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True, index=True)
    is_resolved = db.Column(db.Boolean, default=False, index=True)
    winning_option = db.Column(db.Integer, nullable=True)
    total_pool = db.Column(db.Float, nullable=False, default=0.0)

    # Add relationship for eager loading
    options = db.relationship('PredictionOption', backref='prediction', lazy='joined')
    votes = db.relationship('Vote', backref='prediction', lazy='select')
    bets = db.relationship('Bet', backref='prediction', lazy='select')

    __table_args__ = (
        db.Index('idx_active_created', is_active, created_at.desc()),
        db.Index('idx_resolved_created', is_resolved, created_at.desc())
    )

class PredictionOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prediction_id = db.Column(db.Integer, db.ForeignKey('prediction.id'), nullable=False, index=True)
    text = db.Column(db.String(100), nullable=False)
    votes_count = db.Column(db.Integer, default=0)
    total_bet_amount = db.Column(db.Float, nullable=False, default=0.0)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    prediction_id = db.Column(db.Integer, db.ForeignKey('prediction.id'), nullable=False, index=True)
    option_id = db.Column(db.Integer, db.ForeignKey('prediction_option.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'prediction_id', name='unique_user_prediction_vote'),
        db.Index('idx_vote_user_prediction', user_id, prediction_id)
    )

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='comments')
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]))

class Bet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    prediction_id = db.Column(db.Integer, db.ForeignKey('prediction.id'), nullable=False, index=True)
    option_id = db.Column(db.Integer, db.ForeignKey('prediction_option.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_settled = db.Column(db.Boolean, default=False, index=True)
    winnings = db.Column(db.Float, nullable=True)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'prediction_id', name='unique_user_prediction_bet'),
        db.Index('idx_bet_user_prediction', user_id, prediction_id)
    )

def add_column(engine, table_name, column):
    column_name = column.compile(dialect=engine.dialect)
    column_type = column.type.compile(engine.dialect)
    engine.execute(f'ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {column_type}')

# Initialize database and handle missing columns
with app.app_context():
    inspector = inspect(db.engine)
    
    try:
        # Create all tables first
        db.create_all()
        print("All database tables created successfully")
        
        # Check if prediction-related tables exist
        tables = inspector.get_table_names()
        required_tables = ['prediction', 'prediction_option', 'vote', 'bet']
        missing_tables = [table for table in required_tables if table not in tables]
        
        if missing_tables:
            print(f"Missing tables detected: {missing_tables}")
            # Force create missing tables
            db.create_all()
            print("Attempted to create missing tables")
        
        # Check if columns exist and add them if they don't
        existing_columns = [column['name'] for column in inspector.get_columns('stock')]
        if 'last_viewed' not in existing_columns:
            db.session.execute(text('ALTER TABLE stock ADD COLUMN IF NOT EXISTS last_viewed TIMESTAMP'))
        if 'view_count' not in existing_columns:
            db.session.execute(text('ALTER TABLE stock ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0'))
        if 'trade_count' not in existing_columns:
            db.session.execute(text('ALTER TABLE stock ADD COLUMN IF NOT EXISTS trade_count INTEGER DEFAULT 0'))
        
        # Check prediction table columns
        prediction_columns = [column['name'] for column in inspector.get_columns('prediction')]
        if 'total_pool' not in prediction_columns:
            db.session.execute(text('ALTER TABLE prediction ADD COLUMN IF NOT EXISTS total_pool FLOAT NOT NULL DEFAULT 0.0'))
        
        # Check prediction_option table columns
        option_columns = [column['name'] for column in inspector.get_columns('prediction_option')]
        if 'total_bet_amount' not in option_columns:
            db.session.execute(text('ALTER TABLE prediction_option ADD COLUMN IF NOT EXISTS total_bet_amount FLOAT NOT NULL DEFAULT 0.0'))
        
        db.session.commit()
        print("Database initialization completed successfully")
        
    except Exception as e:
        print(f"Error during database initialization: {str(e)}")
        db.session.rollback()
        raise

def calculate_new_price(current_price, quantity, is_buy):
    # Base impact uses a sigmoid function to create diminishing returns for large quantities
    base_impact = 2 / (1 + math.exp(-0.0001 * quantity)) - 1  # Sigmoid function
    
    # Market sentiment factor (0.8 to 1.2) based on recent price movement
    sentiment = 1.0
    stock_history = StockHistory.query.order_by(StockHistory.timestamp.desc()).limit(10).all()
    if stock_history:
        price_changes = [h.price_change for h in stock_history]
        sentiment = 1.0 + (sum(price_changes) / len(price_changes)) * 0.2  # ±20% sentiment effect
        sentiment = max(0.8, min(1.2, sentiment))  # Clamp between 0.8 and 1.2
    
    # Calculate price impact with sentiment
    impact = base_impact * sentiment
    
    # Apply EMA smoothing (α = 0.2 for smoother transitions)
    alpha = 0.2
    if is_buy:
        target_price = current_price * (1 + impact)
    else:
        target_price = current_price * (1 - impact)
    
    new_price = (alpha * target_price) + ((1 - alpha) * current_price)
    
    # Ensure price doesn't change too drastically (max 10% per transaction)
    max_change = current_price * 0.10
    if abs(new_price - current_price) > max_change:
        new_price = current_price + (max_change if new_price > current_price else -max_change)
    
    # Ensure price stays positive and reasonable
    return max(0.01, min(new_price, current_price * 2))

def calculate_portfolio_value(user_id):
    user = User.query.get(user_id)
    if not user:
        return 0
    
    total_value = user.cash
    positions = Position.query.filter_by(user_id=user_id).all()
    
    for position in positions:
        if position.shares > 0:
            stock = Stock.query.get(position.stock_id)
            total_value += position.shares * stock.price
    
    return total_value

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    # Generate Twitch OAuth URL with all necessary scopes
    params = {
        'client_id': TWITCH_CLIENT_ID,
        'redirect_uri': TWITCH_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'user:read:email openid',
        'force_verify': 'true'  # Force Twitch login screen
    }
    twitch_auth_url = f"https://id.twitch.tv/oauth2/authorize?{urlencode(params)}"
    return render_template('login.html', twitch_auth_url=twitch_auth_url)

@app.route('/auth/twitch/callback')
def twitch_callback():
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    
    if error:
        print(f"Twitch Error: {error} - {error_description}")
        flash(f'Authentication failed: {error_description}', 'error')
        return redirect(url_for('login'))
    
    code = request.args.get('code')
    if not code:
        print("No code received from Twitch")
        flash('Authentication failed: No code received', 'error')
        return redirect(url_for('login'))

    try:
        # Exchange code for access token
        token_url = 'https://id.twitch.tv/oauth2/token'
        token_params = {
            'client_id': TWITCH_CLIENT_ID,
            'client_secret': TWITCH_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': TWITCH_REDIRECT_URI
        }
        
        print("Token params:", token_params)
        token_response = requests.post(token_url, data=token_params)
        print("Token response status:", token_response.status_code)
        print("Token response:", token_response.text)
        
        if token_response.status_code != 200:
            flash(f'Authentication failed: {token_response.text}', 'error')
            return redirect(url_for('login'))
            
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            flash('Failed to get access token from Twitch', 'error')
            return redirect(url_for('login'))

        # Get user info from Twitch
        user_url = 'https://api.twitch.tv/helix/users'
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Client-Id': TWITCH_CLIENT_ID
        }
        user_response = requests.get(user_url, headers=headers)
        print("User response status:", user_response.status_code)
        print("User response:", user_response.text)
        
        if user_response.status_code != 200:
            flash(f'Failed to get user data: {user_response.text}', 'error')
            return redirect(url_for('login'))
        
        user_data = user_response.json().get('data', [])
        if not user_data:
            flash('Failed to get user data from Twitch', 'error')
            return redirect(url_for('login'))
            
        user_data = user_data[0]

        # Find or create user
        user = User.query.filter_by(twitch_id=user_data['id']).first()
        if not user:
            # Check if this is the first user ever
            is_first_user = User.query.count() == 0
            
            # Check if username already exists
            existing_user = User.query.filter_by(username=user_data['login']).first()
            if existing_user:
                flash('Username already exists with different Twitch account', 'error')
                return redirect(url_for('login'))
                
            user = User(
                username=user_data['login'],
                twitch_id=user_data['id'],
                twitch_login=user_data['login'],
                twitch_email=user_data.get('email'),
                twitch_profile_image=user_data.get('profile_image_url'),
                cash=500.0,
                is_approved=True,
                is_admin=is_first_user,  # Make first user admin
                can_add_stocks=is_first_user  # Give first user all permissions
            )
            db.session.add(user)
            try:
                db.session.commit()
                if is_first_user:
                    flash('Account created successfully! You have been granted admin access.', 'success')
                else:
                    flash('Account created successfully! Start trading now.', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Error creating account. Please try again.', 'error')
                return redirect(url_for('login'))

        # Make the session permanent before setting user_id
        session.permanent = True
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))

    except requests.exceptions.RequestException as e:
        flash(f'Authentication failed: Network error', 'error')
        return redirect(url_for('login'))
    except Exception as e:
        flash('An unexpected error occurred', 'error')
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    # Check if user is logged in
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    
    # Get user and verify they exist
    user = User.query.get(session['user_id'])
    if not user:
        # If user doesn't exist, clear session and redirect to login
        session.clear()
        flash('User not found. Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Get stocks and sort by day change
    stocks = Stock.query.all()
    stocks = sorted(stocks, key=lambda x: abs(x.get_day_change()), reverse=True)
    
    # Get user positions
    positions = Position.query.filter_by(user_id=user.id).all()
    positions_dict = {p.stock_id: p for p in positions}
    
    # Calculate portfolio values
    total_investment = user.cash
    total_portfolio_value = user.cash
    day_pl = 0
    total_pl = 0
    
    for position in positions:
        stock = Stock.query.get(position.stock_id)
        if position.shares > 0:
            investment_value = position.shares * stock.initial_price
            current_value = position.shares * stock.price
            day_value_change = position.shares * (stock.price - stock.previous_close)
            
            total_investment += investment_value
            total_portfolio_value += current_value
            day_pl += day_value_change
            total_pl += (current_value - investment_value)
    
    # Calculate percentages
    day_pl_percentage = (day_pl / total_investment * 100) if total_investment > 0 else 0
    total_pl_percentage = (total_pl / total_investment * 100) if total_investment > 0 else 0
    
    # Get rankings data
    users = User.query.all()
    rankings = []
    
    for u in users:
        portfolio_value = calculate_portfolio_value(u.id)
        if portfolio_value <= 500:  # Skip users with no activity (changed from 10000 to 500)
            continue
        
        ranking_entry = {
            'username': u.username,
            'portfolio_value': portfolio_value,
            'value_formatted': f"${portfolio_value:,.2f}",
            'profit_loss': portfolio_value - 500,  # Changed from 10000 to 500
            'profit_loss_formatted': f"${(portfolio_value - 500):,.2f}",
            'profit_loss_percentage': ((portfolio_value - 500) / 500) * 100  # Changed from 10000 to 500
        }
        rankings.append(ranking_entry)
    
    # Sort rankings
    rankings.sort(key=lambda x: x['portfolio_value'], reverse=True)
    
    # Add rank position
    for i, rank in enumerate(rankings):
        rank['position'] = i + 1
    
    return render_template('dashboard.html',
                         user=user,
                         stocks=stocks,
                         positions=positions_dict,
                         total_portfolio_value=total_portfolio_value,
                         day_pl=day_pl,
                         day_pl_percentage=day_pl_percentage,
                         total_pl=total_pl,
                         total_pl_percentage=total_pl_percentage,
                         rankings=rankings)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('welcome'))

@app.route('/trade', methods=['POST'])
def trade():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.form
    
    try:
        # Input validation
        if not all(k in data for k in ['symbol', 'quantity', 'action']):
            return jsonify({'error': 'Missing required fields'}), 400
            
        try:
            quantity = int(data['quantity'])
            if quantity <= 0:
                return jsonify({'error': 'Quantity must be positive'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid quantity'}), 400
            
        if data['action'] not in ['buy', 'sell']:
            return jsonify({'error': 'Invalid action'}), 400
        
        # Get stock and user with row locking to prevent race conditions
        stock = Stock.query.with_for_update().filter_by(symbol=data['symbol']).first()
        if not stock:
            return jsonify({'error': 'Stock not found'}), 404
            
        user = User.query.with_for_update().get(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        position = Position.query.with_for_update().filter_by(
            user_id=user.id, 
            stock_id=stock.id
        ).first()
        
        if not position:
            position = Position(user_id=user.id, stock_id=stock.id, shares=0)
            db.session.add(position)
        
        old_price = stock.price
        
        if data['action'] == 'buy':
            cost = stock.price * quantity
            if user.cash < cost:
                return jsonify({'error': 'Insufficient funds'}), 400
            if stock.shares_held + quantity > stock.total_shares:
                return jsonify({'error': 'Not enough shares available'}), 400
                
            user.cash -= cost
            position.shares += quantity
            stock.shares_held += quantity
            stock.price = calculate_new_price(stock.price, quantity, True)
            stock.trade_count += 1
            
        elif data['action'] == 'sell':
            if position.shares < quantity:
                return jsonify({'error': 'Not enough shares to sell'}), 400
                
            proceeds = stock.price * quantity
            user.cash += proceeds
            position.shares -= quantity
            stock.shares_held -= quantity
            stock.price = calculate_new_price(stock.price, quantity, False)
            stock.trade_count += 1
        
        # Record trade history
        price_change = ((stock.price - old_price) / old_price) * 100
        history = StockHistory(
            stock_id=stock.id,
            price=stock.price,
            price_change=price_change,
            volume=quantity
        )
        db.session.add(history)
        
        try:
            db.session.commit()
            return jsonify({
                'success': True,
                'message': f'Successfully {"bought" if data["action"] == "buy" else "sold"} {quantity} shares of {stock.symbol}',
                'new_balance': user.cash,
                'new_shares': position.shares,
                'new_price': stock.price
            })
        except exc.IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Transaction failed, please try again'}), 500
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/portfolio')
def portfolio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    positions = Position.query.filter_by(user_id=user.id).all()
    
    portfolio = {}
    total_value = user.cash  # Start with cash balance

    for position in positions:
        if position.shares > 0:  # Only show stocks with shares
            stock = Stock.query.get(position.stock_id)
            current_value = position.shares * stock.price
            total_value += current_value
            
            # Calculate average cost and profit/loss
            # For demo, we'll use 100 as the base price
            avg_cost = 100  # In a real app, you'd track purchase history
            total_cost = position.shares * avg_cost
            profit = current_value - total_cost
            profit_percentage = (profit / total_cost) * 100 if total_cost > 0 else 0
            
            portfolio[stock.symbol] = {
                'name': stock.name,
                'shares': position.shares,
                'price': stock.price,
                'value': current_value,
                'avg_cost': avg_cost,
                'profit': profit,
                'profit_percentage': profit_percentage
            }
    
    return render_template('portfolio.html', 
                         user=user, 
                         portfolio=portfolio, 
                         total_value=total_value)

# Add admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Add admin routes
@app.route('/admin')
@admin_required
def admin_panel():
    try:
        users = User.query.all()
        stocks = Stock.query.all()
        
        # Add portfolio values for each user
        user_data = []
        for user in users:
            try:
                portfolio_value = calculate_portfolio_value(user.id)
                user_data.append({
                    'user': user,
                    'portfolio_value': portfolio_value,
                    'formatted_value': f"${portfolio_value:,.2f}"
                })
            except Exception as e:
                print(f"Error calculating portfolio for user {user.id}: {str(e)}")
                continue
        
        return render_template('admin.html',  # Changed from admin/dashboard.html
                             user_data=user_data,
                             stocks=stocks,
                             current_user=User.query.get(session['user_id']))
                             
    except Exception as e:
        print(f"Admin panel error: {str(e)}")
        flash('Error loading admin panel', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/add_stock', methods=['POST'])
@admin_required
def add_stock():
    name = request.form.get('name')
    symbol = request.form.get('symbol')
    price = float(request.form.get('price'))
    description = request.form.get('description', '')
    
    if Stock.query.filter_by(symbol=symbol).first():
        flash('Stock symbol already exists', 'error')
        return redirect(url_for('admin_panel'))
    
    new_stock = Stock(
        name=name,
        symbol=symbol,
        price=price,
        total_shares=1000000,
        shares_held=0,
        previous_close=price,  # Set initial previous close to current price
        initial_price=price    # Set initial price to current price
    )
    
    db.session.add(new_stock)
    db.session.commit()
    flash('Stock added successfully', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle_permission/<int:user_id>')
@admin_required
def toggle_permission(user_id):
    user = User.query.get(user_id)
    if user:
        user.can_add_stocks = not user.can_add_stocks
        db.session.commit()
        return jsonify({
            'success': True,
            'can_add_stocks': user.can_add_stocks,
            'message': f'Permissions updated for {user.username}'
        })
    return jsonify({'success': False, 'message': 'User not found'}), 404

@app.route('/admin/delete_stock/<int:stock_id>', methods=['POST'])
@admin_required
def delete_stock(stock_id):
    stock = Stock.query.get(stock_id)
    if stock:
        # Delete all positions for this stock
        Position.query.filter_by(stock_id=stock_id).delete()
        # Delete all history for this stock
        StockHistory.query.filter_by(stock_id=stock_id).delete()
        # Delete the stock
        db.session.delete(stock)
        db.session.commit()
        flash(f'Stock {stock.symbol} has been deleted', 'success')
    else:
        flash('Stock not found', 'error')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle_admin/<int:user_id>')
@admin_required
def toggle_admin(user_id):
    user = User.query.get(user_id)
    if user:
        # Prevent removing admin status from the last admin
        if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
            return jsonify({
                'success': False,
                'message': 'Cannot remove the last admin user'
            }), 400
            
        user.is_admin = not user.is_admin
        # When making someone admin, also give them stock adding permission
        if user.is_admin:
            user.can_add_stocks = True
        db.session.commit()
        
        return jsonify({
            'success': True,
            'is_admin': user.is_admin,
            'message': f'Admin status {"granted to" if user.is_admin else "revoked from"} {user.username}'
        })
    return jsonify({'success': False, 'message': 'User not found'}), 404

@app.route('/leaderboard')
def leaderboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get all users and calculate their portfolio values
    users = User.query.all()
    leaderboard_data = []
    
    for user in users:
        portfolio_value = calculate_portfolio_value(user.id)
        leaderboard_data.append({
            'username': user.username,
            'profile_image': user.twitch_profile_image,
            'portfolio_value': portfolio_value,
            'cash': user.cash,
            'registration_date': user.registration_date
        })
    
    # Sort users by portfolio value in descending order
    leaderboard_data.sort(key=lambda x: x['portfolio_value'], reverse=True)
    
    # Calculate ranks and find current user's rank
    current_user_rank = None
    for i, data in enumerate(leaderboard_data):
        if data['username'] == User.query.get(session['user_id']).username:
            current_user_rank = i + 1
            break
    
    return render_template('leaderboard.html', 
                         leaderboard=leaderboard_data, 
                         current_user_rank=current_user_rank)

@app.route('/admin/approve_user/<int:user_id>')
@admin_required
def approve_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_approved = not user.is_approved
        db.session.commit()
        return jsonify({
            'success': True,
            'is_approved': user.is_approved,
            'message': f'User {"approved" if user.is_approved else "unapproved"}'
        })
    return jsonify({'success': False, 'message': 'User not found'}), 404

@app.route('/make_first_user_admin')
def make_first_user_admin():
    # Get the first user
    first_user = User.query.order_by(User.id).first()
    if first_user:
        first_user.is_admin = True
        first_user.can_add_stocks = True
        db.session.commit()
        flash('First user has been granted admin access!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/predictions')
def predictions():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('login'))

        active_predictions = (Prediction.query
            .filter_by(is_active=True)
            .order_by(Prediction.created_at.desc())
            .all())

        past_predictions = (Prediction.query
            .filter_by(is_active=False)
            .order_by(Prediction.created_at.desc())
            .limit(10)
            .all())

        # Get user's bets
        bets = Bet.query.filter_by(user_id=user.id).all()
        user_bets = {bet.prediction_id: {
            'option_id': bet.option_id,
            'amount': bet.amount,
            'is_settled': bet.is_settled,
            'winnings': bet.winnings
        } for bet in bets}

        # Get user's votes
        user_votes = {vote.prediction_id: vote.option_id for vote in 
            Vote.query.filter_by(user_id=user.id).all()}

        # Get options for each prediction
        prediction_options = {}
        for pred in active_predictions + past_predictions:
            prediction_options[pred.id] = PredictionOption.query.filter_by(prediction_id=pred.id).all()

        return render_template('predictions.html',
            user=user,
            active_predictions=active_predictions,
            past_predictions=past_predictions,
            prediction_options=prediction_options,
            user_votes=user_votes,
            user_bets=user_bets
        )
    except Exception as e:
        print(f"Error in predictions route: {str(e)}")
        db.session.rollback()
        return "An error occurred: " + str(e), 500

@app.route('/admin/create_prediction', methods=['POST'])
@admin_required
def create_prediction():
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    
    # Validate required fields
    if not all(k in data for k in ['question', 'options', 'duration_hours']):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # Create prediction
        prediction = Prediction(
            question=data['question'],
            created_by=session['user_id'],
            ends_at=datetime.utcnow() + timedelta(hours=int(data['duration_hours'])),
            is_active=True
        )
        db.session.add(prediction)
        db.session.flush()  # Get prediction ID
        
        # Create options
        for option_text in data['options']:
            option = PredictionOption(
                prediction_id=prediction.id,
                text=option_text
            )
            db.session.add(option)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Prediction created successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/vote', methods=['POST'])
def vote():
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first'}), 401
    
    data = request.get_json()
    if not all(k in data for k in ['prediction_id', 'option_id']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        # Check if prediction is still active
        prediction = Prediction.query.get(data['prediction_id'])
        if not prediction or not prediction.is_active:
            return jsonify({'error': 'Prediction is not active'}), 400
        
        # Check if user already voted
        existing_vote = Vote.query.filter_by(
            user_id=session['user_id'],
            prediction_id=data['prediction_id']
        ).first()
        
        if existing_vote:
            return jsonify({'error': 'You have already voted on this prediction'}), 400
        
        # Create vote
        vote = Vote(
            user_id=session['user_id'],
            prediction_id=data['prediction_id'],
            option_id=data['option_id']
        )
        db.session.add(vote)
        
        # Update vote count
        option = PredictionOption.query.get(data['option_id'])
        option.votes_count += 1
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Vote recorded successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/place_bet', methods=['POST'])
def place_bet():
    if 'user_id' not in session:
        return jsonify({'error': 'You must be logged in to place a bet'}), 401

    data = request.get_json()
    prediction_id = data.get('prediction_id')
    option_id = data.get('option_id')
    amount = float(data.get('amount', 0))

    if not all([prediction_id, option_id, amount]) or amount <= 0:
        return jsonify({'error': 'Invalid bet parameters'}), 400

    try:
        # Get prediction and option
        prediction = Prediction.query.get(prediction_id)
        option = PredictionOption.query.get(option_id)
        user = User.query.get(session['user_id'])

        if not prediction or not option:
            return jsonify({'error': 'Invalid prediction or option'}), 404

        # Validate bet conditions
        if not prediction.is_active or prediction.is_resolved:
            return jsonify({'error': 'This prediction is no longer accepting bets'}), 400

        if datetime.utcnow() >= prediction.ends_at:
            return jsonify({'error': 'Betting period has ended'}), 400

        if user.cash < amount:
            return jsonify({'error': 'Insufficient funds'}), 400

        # Check for existing bet
        existing_bet = Bet.query.filter_by(
            user_id=user.id,
            prediction_id=prediction_id
        ).first()

        if existing_bet:
            return jsonify({'error': 'You have already placed a bet on this prediction'}), 400

        # Create bet
        bet = Bet(
            user_id=user.id,
            prediction_id=prediction_id,
            option_id=option_id,
            amount=amount
        )

        # Update user balance and prediction pool
        user.cash -= amount
        prediction.total_pool += amount
        option.total_bet_amount += amount

        db.session.add(bet)
        db.session.commit()

        return jsonify({
            'message': 'Bet placed successfully',
            'new_balance': user.cash
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/resolve_prediction', methods=['POST'])
@admin_required
def resolve_prediction():
    data = request.get_json()
    prediction_id = data.get('prediction_id')
    winning_option_id = data.get('winning_option_id')

    if not all([prediction_id, winning_option_id]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        prediction = Prediction.query.get(prediction_id)
        if not prediction:
            return jsonify({'error': 'Prediction not found'}), 404

        if prediction.is_resolved:
            return jsonify({'error': 'Prediction is already resolved'}), 400

        winning_option = PredictionOption.query.get(winning_option_id)
        if not winning_option:
            return jsonify({'error': 'Invalid winning option'}), 404

        # Calculate winnings
        total_pool = prediction.total_pool
        winning_pool = winning_option.total_bet_amount

        if winning_pool > 0:
            # Get winning bets
            winning_bets = Bet.query.filter_by(
                prediction_id=prediction_id,
                option_id=winning_option_id
            ).all()

            # Calculate profit pool (90% of losing bets)
            losing_pool = total_pool - winning_pool
            profit_pool = losing_pool * 0.9  # 10% house fee

            # Distribute winnings
            for bet in winning_bets:
                share = bet.amount / winning_pool
                winnings = bet.amount + (profit_pool * share)
                
                bet.is_settled = True
                bet.winnings = winnings
                
                # Update user balance
                user = User.query.get(bet.user_id)
                user.cash += winnings

        # Mark losing bets as settled
        Bet.query.filter(
            Bet.prediction_id == prediction_id,
            Bet.option_id != winning_option_id
        ).update({
            'is_settled': True,
            'winnings': 0
        })

        # Update prediction
        prediction.is_resolved = True
        prediction.is_active = False
        prediction.winning_option = winning_option_id

        db.session.commit()
        return jsonify({'message': 'Prediction resolved successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete_prediction/<int:prediction_id>', methods=['POST'])
@admin_required
def delete_prediction(prediction_id):
    try:
        prediction = Prediction.query.get(prediction_id)
        if not prediction:
            return jsonify({'error': 'Prediction not found'}), 404
        
        # Delete associated votes and options
        Vote.query.filter_by(prediction_id=prediction_id).delete()
        PredictionOption.query.filter_by(prediction_id=prediction_id).delete()
        db.session.delete(prediction)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Prediction deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/stock/<symbol>')
def stock_detail(symbol):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    stock = Stock.query.filter_by(symbol=symbol).first_or_404()
    user = User.query.get(session['user_id'])
    
    # Update view statistics
    stock.view_count += 1
    stock.last_viewed = datetime.utcnow()
    db.session.commit()
    
    # Get stock history for the graph
    history = StockHistory.query.filter_by(stock_id=stock.id)\
        .order_by(StockHistory.timestamp.desc())\
        .limit(100)\
        .all()
    history.reverse()  # Show oldest to newest
    
    # Format data for the graph
    graph_data = {
        'timestamps': [h.timestamp.strftime('%Y-%m-%d %H:%M:%S') for h in history],
        'prices': [float(h.price) for h in history],
        'volumes': [h.volume for h in history]
    }
    
    # Get comments with replies
    comments = Comment.query.filter_by(stock_id=stock.id, parent_id=None)\
        .order_by(Comment.created_at.desc())\
        .all()
    
    return render_template('stock_detail.html',
                         stock=stock,
                         user=user,
                         graph_data=graph_data,
                         comments=comments)

@app.route('/api/stock/<symbol>/history')
def stock_history(symbol):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    stock = Stock.query.filter_by(symbol=symbol).first_or_404()
    history = StockHistory.query.filter_by(stock_id=stock.id)\
        .order_by(StockHistory.timestamp.desc())\
        .limit(100)\
        .all()
    history.reverse()
    
    return jsonify({
        'timestamps': [h.timestamp.strftime('%Y-%m-%d %H:%M:%S') for h in history],
        'prices': [float(h.price) for h in history],
        'volumes': [h.volume for h in history]
    })

@app.route('/api/stock/<symbol>/comment', methods=['POST'])
def add_comment(symbol):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    stock = Stock.query.filter_by(symbol=symbol).first_or_404()
    data = request.get_json()
    
    try:
        comment = Comment(
            user_id=session['user_id'],
            stock_id=stock.id,
            content=data['content'],
            parent_id=data.get('parent_id')
        )
        db.session.add(comment)
        stock.comment_count += 1  # Increment comment count
        db.session.commit()
        
        return jsonify({
            'id': comment.id,
            'content': comment.content,
            'username': comment.user.username,
            'profile_image': comment.user.twitch_profile_image,
            'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

def update_stock_prices():
    """
    Background task to update stock prices based on user interest
    Uses batch processing and efficient data structures
    Time Complexity: O(n log n) where n is number of stocks
    Space Complexity: O(n)
    """
    try:
        with app.app_context():
            # Get all stocks with a single query
            stocks = Stock.query.with_for_update().all()
            updates = []
            histories = []
            
            current_time = datetime.utcnow()
            
            for stock in stocks:
                try:
                    # Calculate interest score
                    interest_score = stock.calculate_interest_score()
                    
                    # Use interest score to determine update probability
                    if random.random() < (interest_score / 10):  # Normalized probability
                        # Calculate volatility based on interest
                        base_volatility = 0.002  # 0.2% base volatility
                        max_volatility = 0.015   # 1.5% max volatility
                        
                        # Sigmoid function for smooth volatility scaling
                        volatility = base_volatility + (max_volatility - base_volatility) * (
                            1 / (1 + math.exp(-2 * (interest_score - 2)))
                        
                        # Calculate price change
                        change_percentage = random.uniform(-volatility, volatility)
                        old_price = stock.price
                        new_price = old_price * (1 + change_percentage)
                        
                        # Apply price bounds
                        min_price = max(0.01, stock.initial_price * 0.2)
                        max_price = stock.initial_price * 5
                        new_price = max(min_price, min(max_price, new_price))
                        
                        # Prepare updates
                        stock.previous_close = stock.price
                        stock.price = new_price
                        
                        # Calculate trading volume based on interest
                        volume = int(10 + interest_score * 20)  # Base volume + interest-based volume
                        
                        # Create history record
                        history = StockHistory(
                            stock_id=stock.id,
                            price=new_price,
                            price_change=((new_price - old_price) / old_price) * 100,
                            volume=volume,
                            timestamp=current_time
                        )
                        histories.append(history)
                        
                except Exception as e:
                    print(f"Error updating stock {stock.symbol}: {str(e)}")
                    continue
            
            try:
                # Batch insert histories
                if histories:
                    db.session.bulk_save_objects(histories)
                db.session.commit()
            except Exception as e:
                print(f"Error committing updates: {str(e)}")
                db.session.rollback()
    
    except Exception as e:
        print(f"Error in update_stock_prices: {str(e)}")

def create_scheduler():
    """Create and configure the scheduler with proper error handling"""
    try:
        scheduler = BackgroundScheduler(
            daemon=True,
            job_defaults={
                'coalesce': True,
                'max_instances': 1,
                'misfire_grace_time': 15
            }
        )
        
        # Add the stock update job
        scheduler.add_job(
            func=update_stock_prices,
            trigger="interval",
            seconds=45,
            max_instances=1
        )
        
        def cleanup():
            try:
                if scheduler.running:
                    scheduler.shutdown(wait=False)
            except:
                pass
        
        atexit.register(cleanup)
        scheduler.start()
        return scheduler
        
    except Exception as e:
        print(f"Error creating scheduler: {str(e)}")
        return None

# Initialize scheduler only in a web process
scheduler = None
if os.environ.get('RAILWAY_ENVIRONMENT') == 'production':
    if not os.environ.get('DYNO') or not os.environ.get('DYNO').startswith('web'):
        scheduler = None
    else:
        scheduler = create_scheduler()
elif not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    scheduler = create_scheduler()

# Add health check endpoint for Railway
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'}), 200

def invalidate_user_cache(user_id):
    """Invalidate all cached data for a user"""
    cache.delete(CACHE_KEYS['user_portfolio'].format(user_id))
    cache.delete(CACHE_KEYS['user_bets'].format(user_id))

def invalidate_prediction_cache(prediction_id):
    """Invalidate prediction-related caches"""
    cache.delete(CACHE_KEYS['prediction_data'].format(prediction_id))
    cache.delete(CACHE_KEYS['active_predictions'])

# Add database session middleware
@app.before_request
def before_request():
    g.db = db.session()

@app.teardown_request
def teardown_request(exception=None):
    if hasattr(g, 'db'):
        g.db.close()

# Add database health check
def check_db_connection():
    try:
        db.session.execute('SELECT 1')
        return True
    except Exception as e:
        print(f"Database connection error: {str(e)}")
        return False

# Periodic database connection check
def periodic_db_check():
    if not check_db_connection():
        db.session.remove()
        db.engine.dispose()

scheduler.add_job(
    func=periodic_db_check,
    trigger="interval",
    minutes=5
)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 