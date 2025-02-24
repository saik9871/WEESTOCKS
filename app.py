from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
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

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Use DATABASE_URL from environment variables, fallback to SQLite for local development
database_url = os.getenv('DATABASE_URL', 'postgresql://neondb_owner:npg_G9shViASrx8J@ep-late-unit-a80vzjan-pooler.eastus2.azure.neon.tech/neondb?sslmode=require')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)  # Session lasts for 31 days

# Twitch OAuth Configuration
TWITCH_CLIENT_ID = 'shdewm91zxskpkg12fi3hphsfsajlc'
TWITCH_CLIENT_SECRET = 'q4kuhmknmf7i56mxwz4tfkkad18av3'
TWITCH_REDIRECT_URI = 'https://weenstock.up.railway.app/auth/twitch/callback'  # Updated to production URL

db = SQLAlchemy(app)

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
    is_approved = db.Column(db.Boolean, default=True)  # Changed to True
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
    previous_close = db.Column(db.Float, nullable=False, default=0.0)  # For day change calculation
    initial_price = db.Column(db.Float, nullable=False)  # For net change calculation

    def get_day_change(self):
        if self.previous_close == 0:
            return 0
        return ((self.price - self.previous_close) / self.previous_close) * 100

    def get_net_change(self):
        if self.initial_price == 0:
            return 0
        return ((self.price - self.initial_price) / self.initial_price) * 100

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
    is_active = db.Column(db.Boolean, default=True)
    is_resolved = db.Column(db.Boolean, default=False)
    winning_option = db.Column(db.Integer, nullable=True)  # ID of the winning option

class PredictionOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prediction_id = db.Column(db.Integer, db.ForeignKey('prediction.id'), nullable=False)
    text = db.Column(db.String(100), nullable=False)
    votes_count = db.Column(db.Integer, default=0)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prediction_id = db.Column(db.Integer, db.ForeignKey('prediction.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('prediction_option.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Ensure users can only vote once per prediction
    __table_args__ = (db.UniqueConstraint('user_id', 'prediction_id', name='unique_user_prediction_vote'),)

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

# Add this model for bot configuration
class BotConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    token_expires_at = db.Column(db.DateTime)
    channel_name = db.Column(db.String(100), default='JasonTheWeen')
    is_active = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Initialize database and add initial stocks only if they don't exist
with app.app_context():
    db.create_all()  # This will create tables if they don't exist
    
    # Add initial stocks only if the stocks table is empty
    if not Stock.query.first():
        initial_stocks = [
            Stock(
                symbol='BAJAJST',
                name='Bajaj Stock',
                price=930.00,
                total_shares=1000000,
                shares_held=0,
                previous_close=836.48,  # Previous day's close
                initial_price=301.71    # Initial price
            ),
            Stock(
                symbol='TITANBIO',
                name='Titan Bio Corp',
                price=811.90,
                total_shares=1000000,
                shares_held=0,
                previous_close=790.82,
                initial_price=466.05
            ),
            Stock(
                symbol='SURAJ',
                name='Suraj Limited',
                price=499.20,
                total_shares=1000000,
                shares_held=0,
                previous_close=493.82,
                initial_price=431.89
            )
        ]
        for stock in initial_stocks:
            db.session.add(stock)
        db.session.commit()
        print("Initial stocks added to database")

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
        return redirect(url_for('login'))
    
    data = request.form
    stock = Stock.query.filter_by(symbol=data['symbol']).first()
    user = User.query.get(session['user_id'])
    quantity = int(data['quantity'])
    action = data['action']
    
    if not stock or not user:
        flash('Invalid stock or user', 'error')
        return redirect(url_for('dashboard'))
    
    position = Position.query.filter_by(user_id=user.id, stock_id=stock.id).first()
    if not position:
        position = Position(user_id=user.id, stock_id=stock.id, shares=0)
        db.session.add(position)
    
    try:
        old_price = stock.price
        if action == 'buy':
            cost = stock.price * quantity
            if user.cash < cost:
                flash('Insufficient funds', 'error')
                return redirect(url_for('dashboard'))
            if stock.shares_held + quantity > stock.total_shares:
                flash('Not enough shares available', 'error')
                return redirect(url_for('dashboard'))
                
            user.cash -= cost
            position.shares += quantity
            stock.shares_held += quantity
            stock.price = calculate_new_price(stock.price, quantity, True)
            
            # Record trade history
            price_change = ((stock.price - old_price) / old_price) * 100
            history = StockHistory(
                stock_id=stock.id,
                price=stock.price,
                price_change=price_change,
                volume=quantity
            )
            db.session.add(history)
            
            flash(f'Successfully bought {quantity} shares of {stock.symbol}', 'success')
            
        elif action == 'sell':
            if position.shares < quantity:
                flash('Not enough shares to sell', 'error')
                return redirect(url_for('dashboard'))
                
            proceeds = stock.price * quantity
            user.cash += proceeds
            position.shares -= quantity
            stock.shares_held -= quantity
            stock.price = calculate_new_price(stock.price, quantity, False)
            
            # Record trade history
            price_change = ((stock.price - old_price) / old_price) * 100
            history = StockHistory(
                stock_id=stock.id,
                price=stock.price,
                price_change=price_change,
                volume=quantity
            )
            db.session.add(history)
            
            flash(f'Successfully sold {quantity} shares of {stock.symbol}', 'success')
        
        db.session.commit()
    except Exception as e:
        flash('An error occurred during the trade', 'error')
        
    return redirect(url_for('dashboard'))

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
    users = User.query.all()
    stocks = Stock.query.all()
    
    # Add portfolio values for each user
    user_data = []
    for user in users:
        portfolio_value = calculate_portfolio_value(user.id)
        user_data.append({
            'user': user,
            'portfolio_value': portfolio_value,
            'formatted_value': f"${portfolio_value:,.2f}"
        })
    
    # Get bot status
    bot_config = BotConfig.query.first()
    bot_status = {
        'is_configured': bool(bot_config and bot_config.access_token),
        'last_updated': bot_config.updated_at if bot_config else None
    }
    
    return render_template('admin/dashboard.html', 
                         user_data=user_data,
                         stocks=stocks,
                         bot_status=bot_status,
                         current_user=User.query.get(session['user_id']))

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
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Get active and past predictions
    active_predictions = Prediction.query.filter_by(is_active=True).order_by(Prediction.created_at.desc()).all()
    past_predictions = Prediction.query.filter_by(is_active=False).order_by(Prediction.created_at.desc()).limit(10).all()
    
    # Get user's votes
    user_votes = Vote.query.filter_by(user_id=user.id).all()
    user_votes_dict = {vote.prediction_id: vote.option_id for vote in user_votes}
    
    # Get options for each prediction
    prediction_options = {}
    for pred in active_predictions + past_predictions:
        options = PredictionOption.query.filter_by(prediction_id=pred.id).all()
        prediction_options[pred.id] = options
    
    return render_template('predictions.html',
                         user=user,
                         active_predictions=active_predictions,
                         past_predictions=past_predictions,
                         prediction_options=prediction_options,
                         user_votes=user_votes_dict)

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

@app.route('/admin/resolve_prediction', methods=['POST'])
@admin_required
def resolve_prediction():
    data = request.get_json()
    if not all(k in data for k in ['prediction_id', 'winning_option_id']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        prediction = Prediction.query.get(data['prediction_id'])
        if not prediction:
            return jsonify({'error': 'Prediction not found'}), 404
        
        prediction.is_active = False
        prediction.is_resolved = True
        prediction.winning_option = data['winning_option_id']
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Prediction resolved successfully'})
    
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

# Add these routes for bot authentication
@app.route('/admin/bot/auth')
@admin_required
def bot_auth():
    """Start the bot authentication process"""
    try:
        # Generate state token for security
        state = secrets.token_hex(16)
        session['oauth_state'] = state
        
        # Define OAuth parameters
        params = {
            'client_id': TWITCH_CLIENT_ID,
            'redirect_uri': 'https://weenstock.up.railway.app/auth/bot/callback',
            'response_type': 'code',
            'scope': 'chat:read chat:edit',
            'state': state,
            'force_verify': 'true'
        }
        
        # Construct auth URL
        auth_url = f"https://id.twitch.tv/oauth2/authorize?{urlencode(params)}"
        
        return render_template('admin/bot_auth.html', auth_url=auth_url)
        
    except Exception as e:
        flash(f'Error initiating bot authentication: {str(e)}', 'error')
        return redirect(url_for('admin_panel'))

@app.route('/auth/bot/callback')
@admin_required
def bot_callback():
    """Handle the callback from Twitch OAuth"""
    try:
        # Verify state
        state = request.args.get('state')
        if state != session.get('oauth_state'):
            flash('Invalid state parameter', 'error')
            return redirect(url_for('admin_panel'))
        
        # Get authorization code
        code = request.args.get('code')
        if not code:
            flash('No authorization code received', 'error')
            return redirect(url_for('admin_panel'))
        
        # Exchange code for tokens
        token_url = 'https://id.twitch.tv/oauth2/token'
        data = {
            'client_id': TWITCH_CLIENT_ID,
            'client_secret': TWITCH_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://weenstock.up.railway.app/auth/bot/callback'
        }
        
        response = requests.post(token_url, data=data)
        if response.status_code != 200:
            flash('Failed to get access token', 'error')
            return redirect(url_for('admin_panel'))
        
        token_data = response.json()
        
        # Store tokens in database
        bot_config = BotConfig.query.first()
        if not bot_config:
            bot_config = BotConfig()
        
        bot_config.access_token = token_data['access_token']
        bot_config.refresh_token = token_data['refresh_token']
        bot_config.token_expires_at = datetime.utcnow() + timedelta(seconds=token_data['expires_in'])
        bot_config.is_active = True
        
        db.session.add(bot_config)
        db.session.commit()
        
        # Start the bot
        start_bot(bot_config.access_token)
        
        flash('Bot authenticated successfully!', 'success')
        return redirect(url_for('admin_panel'))
        
    except Exception as e:
        flash(f'Error during bot authentication: {str(e)}', 'error')
        return redirect(url_for('admin_panel'))

# Add this template for bot authentication
@app.route('/admin/bot/status')
@admin_required
def bot_status():
    """Check bot status and refresh token if needed"""
    try:
        bot_config = BotConfig.query.first()
        if not bot_config or not bot_config.is_active:
            return jsonify({
                'status': 'inactive',
                'message': 'Bot is not configured'
            })
        
        # Check if token needs refresh
        if bot_config.token_expires_at <= datetime.utcnow():
            # Refresh token
            token_url = 'https://id.twitch.tv/oauth2/token'
            data = {
                'client_id': TWITCH_CLIENT_ID,
                'client_secret': TWITCH_CLIENT_SECRET,
                'grant_type': 'refresh_token',
                'refresh_token': bot_config.refresh_token
            }
            
            response = requests.post(token_url, data=data)
            if response.status_code == 200:
                token_data = response.json()
                bot_config.access_token = token_data['access_token']
                bot_config.refresh_token = token_data['refresh_token']
                bot_config.token_expires_at = datetime.utcnow() + timedelta(seconds=token_data['expires_in'])
                db.session.commit()
                
                # Restart bot with new token
                start_bot(bot_config.access_token)
            else:
                bot_config.is_active = False
                db.session.commit()
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to refresh token'
                })
        
        return jsonify({
            'status': 'active',
            'expires_at': bot_config.token_expires_at.isoformat(),
            'channel': bot_config.channel_name
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True) 