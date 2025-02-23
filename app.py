from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import math
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Use DATABASE_URL from environment variables, fallback to SQLite for local development
database_url = os.getenv('DATABASE_URL', 'sqlite:///weestocks.db')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    cash = db.Column(db.Float, nullable=False, default=10000.0)
    is_admin = db.Column(db.Boolean, default=False)
    can_add_stocks = db.Column(db.Boolean, default=False)

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

# Initialize database and add initial stocks only if they don't exist
with app.app_context():
    db.create_all()  # This will create tables if they don't exist
    
    # Create initial admin user if no users exist
    if not User.query.filter_by(is_admin=True).first():
        admin_user = User(
            username='admin',
            cash=10000.0,
            is_admin=True
        )
        admin_user.set_password('Ts29bp6573#')  # Updated secure password
        db.session.add(admin_user)
        db.session.commit()
        print("Initial admin user created:")
        print("Username: admin")
        print("Password: Ts29bp6573#")
    else:
        # Update existing admin password if needed
        admin_user = User.query.filter_by(username='admin').first()
        admin_user.set_password('Ts29bp6573#')
        db.session.commit()
        print("Admin password updated successfully")
    
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))
        
        user = User(username=username, cash=500.0)  # Changed initial balance to 500
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    stocks = Stock.query.all()
    
    # Sort stocks by day change percentage (trending stocks first)
    stocks = sorted(stocks, key=lambda x: abs(x.get_day_change()), reverse=True)
    
    positions = Position.query.filter_by(user_id=user.id).all()
    
    # Create positions dictionary for easy lookup
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
    
    # Get rankings data for the leaderboard
    users = User.query.all()
    rankings = []
    
    for u in users:
        portfolio_value = calculate_portfolio_value(u.id)
        if portfolio_value <= 10000:  # Skip users with no activity
            continue
        
        ranking_entry = {
            'username': u.username,
            'portfolio_value': portfolio_value,
            'value_formatted': f"${portfolio_value:,.2f}",
            'profit_loss': portfolio_value - 10000,
            'profit_loss_formatted': f"${(portfolio_value - 10000):,.2f}",
            'profit_loss_percentage': ((portfolio_value - 10000) / 10000) * 100
        }
        rankings.append(ranking_entry)
    
    # Sort rankings by portfolio value
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
                         rankings=rankings)  # Add rankings to template context

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
    return render_template('admin.html', users=users, stocks=stocks)

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

@app.route('/leaderboard')
def leaderboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    timeframe = request.args.get('timeframe', 'all')  # all, weekly, monthly
    response_format = request.args.get('format', 'html')  # html or json
    
    # Get current user
    current_user = User.query.get(session['user_id'])
    
    # Get all users
    users = User.query.all()
    
    # Calculate portfolio values and create ranking data
    rankings = []
    now = datetime.utcnow()
    
    for user in users:
        portfolio_value = calculate_portfolio_value(user.id)
        
        # Skip users with no activity
        if portfolio_value <= 10000:  # Initial cash amount
            continue
            
        ranking_entry = {
            'username': user.username,
            'portfolio_value': portfolio_value,
            'value_formatted': f"${portfolio_value:,.2f}",
            'profit_loss': portfolio_value - 10000,  # Compared to initial cash
            'profit_loss_formatted': f"${(portfolio_value - 10000):,.2f}",
            'profit_loss_percentage': ((portfolio_value - 10000) / 10000) * 100
        }
        rankings.append(ranking_entry)
    
    # Sort rankings by portfolio value (descending)
    rankings.sort(key=lambda x: x['portfolio_value'], reverse=True)
    
    # Add rank position
    for i, rank in enumerate(rankings):
        rank['position'] = i + 1
    
    # Filter based on timeframe
    if timeframe == 'weekly':
        week_ago = now - timedelta(days=7)
        # In a real app, you'd filter based on historical data
        rankings = rankings[:10]  # Simplified: just show top 10 for demo
    elif timeframe == 'monthly':
        month_ago = now - timedelta(days=30)
        # In a real app, you'd filter based on historical data
        rankings = rankings[:20]  # Simplified: just show top 20 for demo
    
    if response_format == 'json':
        return jsonify({
            'rankings': rankings,
            'current_time': now.strftime('%Y-%m-%d %H:%M:%S UTC')
        })
    
    return render_template('leaderboard.html',
                         rankings=rankings,
                         timeframe=timeframe,
                         current_time=now.strftime('%Y-%m-%d %H:%M:%S UTC'),
                         session_username=current_user.username)

if __name__ == '__main__':
    app.run(debug=True) 