from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from markupsafe import escape
from forms import EmptyForm
import re, logging
from logging.handlers import RotatingFileHandler
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///snackshop.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
migrate = Migrate(app,db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)

class Snack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)

class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    snack_id = db.Column(db.Integer, db.ForeignKey('snack.id'), nullable=False)

class LikedSnack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    snack_id = db.Column(db.Integer, db.ForeignKey('snack.id'), nullable=False)

class Cart(db.Model):
    __tablename__ = 'cart'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    items = db.relationship('CartItem', backref='cart', lazy=True)

class CartItem(db.Model):
    __tablename__ = 'cart_item'
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    snack_id = db.Column(db.Integer, db.ForeignKey('snack.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    
    snack = db.relationship('Snack', backref='cart_items', lazy=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    order_items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    snack_id = db.Column(db.Integer, db.ForeignKey('snack.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    snack = db.relationship('Snack', backref=db.backref('order_items', lazy=True))

@app.route('/')
def index():
    form = EmptyForm()
    snacks = Snack.query.all()
    return render_template('index.html', snacks=snacks, form=form)

def is_password_strong(password):
    if (len(password) < 8 or
        not re.search("[a-z]", password) or
        not re.search("[A-Z]", password) or
        not re.search("[0-9]", password) or
        not re.search("[@#$%^&+=]", password)):
        return False
    return True

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = EmptyForm()
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['reg_email']
        password = request.form['reg_password']
        confirm_password = request.form['confirm_password']

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            error = "Invalid email format."
            app.logger.warning(f"Registration failed: Invalid email format for {email}")
            return render_template('register.html', error=error, form=form)

        if password != confirm_password:
            error = "Passwords do not match."
            app.logger.warning(f"Registration failed: Passwords do not match for user {username}")
            return render_template('register.html', error=error, form=form)

        if not is_password_strong(password):
            error = "Password must be at least 8 characters long and include uppercase, lowercase, digits, and special characters."
            app.logger.warning(f"Registration failed: Weak password for user {username}")
            return render_template('register.html', error=error, form=form)

        username = escape(username)
        email = escape(email)
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = EmptyForm()
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            error = "Invalid email format."
            app.logger.warning(f"Login failed: Invalid email format for {email}")
            return render_template('login.html', error=error, form=form)

        email = escape(email)
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear() 
            session['user_id'] = user.id
            session['logged_in'] = True
            return redirect(url_for('profile'))
        else:
            error = "Invalid email or password."
            app.logger.warning(f"Login failed: Invalid credentials for {email}")
            return render_template('login.html', error=error, form=form)

    return render_template('login.html', form=form)

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('index'))
    return wrap

@app.route('/logout')
def logout():
    session.clear() 
    return redirect(url_for('index'))

@app.route('/profile')
@is_logged_in
def profile():
    form = EmptyForm()
    user_id = session['user_id']

    if user_id:
        user = User.query.filter_by(id=user_id).first()
        cart = Cart.query.filter_by(user_id=user_id).first()
        detailed_cart_items = []
        if cart:
            cart_items = CartItem.query.filter_by(cart_id=cart.id).all()
            for item in cart_items:
                snack = Snack.query.get(item.snack_id)
                if snack:
                    detailed_cart_items.append({
                        'cart_item_id': item.id,
                        'name': snack.name,
                        'price': snack.price,
                        'quantity': item.quantity,
                        'item_total': snack.price * item.quantity
                    })

        wishlist = Wishlist.query.filter_by(user_id=user_id).all()
        liked_snacks = LikedSnack.query.filter_by(user_id=user_id).all()
        liked_snacks_list = [Snack.query.get(liked_snack.snack_id) for liked_snack in liked_snacks]
        orders = Order.query.filter_by(user_id=user_id).all()

        return render_template(
            'profile.html',
            user=user,
            wishlist=wishlist,
            liked_snacks=liked_snacks_list,
            cart_items=detailed_cart_items,
            orders=orders,
            form=form
        )
    else:
        return redirect(url_for('index'))

@app.route('/add_to_wishlist/<int:snack_id>', methods=['POST'])
def add_to_wishlist(snack_id):
    if 'user_id' not in session or not session.get('logged_in'):
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    new_wishlist_item = Wishlist(user_id=user_id, snack_id=snack_id)
    
    db.session.add(new_wishlist_item)
    db.session.commit()
    
    return redirect(url_for('index'))

@app.route('/like_snack/<int:snack_id>', methods=['POST'])
def like_snack(snack_id):
    if 'user_id' in session:
        user_id = session['user_id']
        liked_snack = LikedSnack(user_id=user_id, snack_id=snack_id)
        db.session.add(liked_snack)
        db.session.commit()
        return redirect(url_for('shop'))
    return redirect(url_for('index'))

@app.route('/toggle_like/<int:snack_id>', methods=['POST'])
@csrf.exempt
def toggle_like(snack_id):
    form = EmptyForm() 
    if form.validate_on_submit():
        if 'user_id' in session:
            user_id = session['user_id']
            existing_like = LikedSnack.query.filter_by(user_id=user_id, snack_id=snack_id).first()
            
            if existing_like:
                db.session.delete(existing_like)
            else:
                new_like = LikedSnack(user_id=user_id, snack_id=snack_id)
                db.session.add(new_like)
            
            db.session.commit()
            
            next_page = request.form.get("next_page", "profile")
            return redirect(url_for(next_page))
    return redirect(url_for('index'))

@app.route('/shop')
def shop():
    form = EmptyForm()
    if 'user_id' in session:
        user_id = session['user_id']
        liked_snacks = [like.snack_id for like in LikedSnack.query.filter_by(user_id=user_id).all()]
    else:
        user_id = None
        liked_snacks = []

    snacks = Snack.query.all()
    return render_template('shop.html', snacks=snacks, liked_snacks=liked_snacks, form=form, user_id=user_id)

@app.route('/add_to_cart/<int:snack_id>', methods=['POST'])
@csrf.exempt
def add_to_cart(snack_id):
    form = EmptyForm()
    if form.validate_on_submit():
        if 'user_id' not in session:
            return redirect(url_for('index'))

        snack = Snack.query.get(snack_id)
        if not snack:
            flash("Snack not found.")
            return redirect(url_for('shop'))

        try:
            quantity = int(request.form['quantity'])
            if quantity <= 0:
                raise ValueError
        except (ValueError, TypeError):
            flash("Invalid quantity.")
            return redirect(url_for('shop'))

        user_id = session['user_id']
        cart = Cart.query.filter_by(user_id=user_id).first()
        if not cart:
            cart = Cart(user_id=user_id)
            db.session.add(cart)
            db.session.commit()

        cart_item = CartItem.query.filter_by(cart_id=cart.id, snack_id=snack_id).first()
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(cart_id=cart.id, snack_id=snack_id, quantity=quantity)
            db.session.add(cart_item)

        db.session.commit()

        flash(f"{escape(snack.name)} has been added to your cart.")
        return redirect(url_for('shop'))
    return redirect(url_for('shop'))

@app.route('/remove_from_cart/<int:cart_item_id>', methods=['POST'])
def remove_from_cart(cart_item_id):
    if 'user_id' in session:
        cart_item = CartItem.query.get(cart_item_id)
        if cart_item and cart_item.cart.user_id == session['user_id']:
            db.session.delete(cart_item)
            db.session.commit()
            flash('Item removed from cart', 'success')
        else:
            flash('Item not found or unauthorized action', 'error')
    return redirect(url_for('checkout'))

@app.route('/checkout', methods=['GET', 'POST'])
@is_logged_in
def checkout():
    form = EmptyForm()

    user_id = session['user_id']
    cart = Cart.query.filter_by(user_id=user_id).first()

    if not cart:
        flash("Cart is empty.")
        return redirect(url_for('shop'))

    cart_items = CartItem.query.filter_by(cart_id=cart.id).all()

    detailed_items = []
    for item in cart_items:
        snack = Snack.query.get(item.snack_id)
        if snack:
            detailed_items.append({
                'cart_item_id': item.id,
                'name': snack.name,
                'price': snack.price,
                'quantity': item.quantity,
                'item_total': snack.price * item.quantity
            })

    if request.method == 'POST':
        try:
            order = Order(user_id=user_id)
            db.session.add(order)
            db.session.commit()

            for item in cart_items:
                order_item = OrderItem(order_id=order.id, snack_id=item.snack_id, quantity=item.quantity)
                db.session.add(order_item)
            
            db.session.commit()
            CartItem.query.filter_by(cart_id=cart.id).delete()
            db.session.delete(cart)
            db.session.commit()
            
            flash("Thank you for your purchase!")
            return redirect(url_for('profile'))
        
        except Exception as e:
            app.logger.error(f"Checkout failed: {e}")
            flash("An error occurred during checkout. Please try again.")
            return redirect(url_for('checkout'))

    total = sum(item['item_total'] for item in detailed_items)

    return render_template('checkout.html', cart_items=detailed_items, total="{:.2f}".format(total), form=form)

@app.context_processor
def inject_cart_items():
    form = EmptyForm()
    cart_items = None
    if 'user_id' in session:
        user_id = session['user_id']
        cart = Cart.query.filter_by(user_id=user_id).first()
        if cart:
            cart_items = CartItem.query.filter_by(cart_id=cart.id).all()
    return dict(cart_items=cart_items)

@app.route('/order_history')
@is_logged_in
def order_history():
    user_id = session['user_id']
    orders = Order.query.filter_by(user_id=user_id).all()
    form = EmptyForm() 
    return render_template('order_history.html', orders=orders, form=form)    

@app.route('/about')
def about():
    form = EmptyForm()
    return render_template('about.html', form=form)

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.teardown_request
def clear_session_on_teardown(exception=None):
    session.clear()

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f'Unhandled Exception: {e}')
    return render_template('error.html', error=str(e)), 500

if __name__ == '__main__':
    handler = RotatingFileHandler('error.log', maxBytes=10000, backupCount=1) 
    handler.setLevel(logging.ERROR) 
    app.logger.addHandler(handler)
    with app.app_context():
        db.create_all()
        if not Snack.query.all():
            db.session.add_all([
                Snack(name="Chips", description="Crunchy and salty", price=1.99),
                Snack(name="Cookies", description="Sweet and chewy", price=2.49),
                Snack(name="Gummies", description="Fruity and chewy", price=1.49),
                Snack(name="Pretzels", description="Salty and satisfying", price=1.79),
                Snack(name="Chocolate", description="Rich and sweet", price=2.99),
            ])
            db.session.commit()
    
    app.run(debug=True)