from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, logging, stripe, jwt, bcrypt, re, io, requests
from datetime import datetime, timedelta
from redis import Redis
from functools import wraps
from PIL import Image
from dotenv import load_dotenv


load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


try:
    redis_client = Redis(host='localhost', port=6379, db=0)
    redis_client.ping()  # Test connection
except:
    logging.warning("Redis connection failed. Rate limiting will be disabled.")
    redis_client = None
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')


logging.basicConfig(filename='error.log', level=logging.ERROR)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    uploads = db.relationship('Photo', backref='user', lazy=True)
    usage_count = db.Column(db.Integer, default=0)
    is_premium = db.Column(db.Boolean, default=False)
    stripe_customer_id = db.Column(db.String(150), unique=True, nullable=True)

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    analysis_result = db.Column(db.String(300))  # To store detection results

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    stripe_payment_id = db.Column(db.String(150), unique=True, nullable=False)


def rate_limit(requests_per_minute=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if redis_client is None:
                return f(*args, **kwargs)
            ip = request.remote_addr
            key = f'rate_limit:{ip}'
            request_count = redis_client.get(key)
            
            if request_count is None:
                redis_client.setex(key, timedelta(minutes=1), 1)
            elif int(request_count) >= requests_per_minute:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': redis_client.ttl(key)
                }), 429
            else:
                redis_client.incr(key)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except stripe.error.CardError as e:
            logging.error(f"Card Error: {str(e)}")
            return jsonify({'error': 'Your card was declined'}), 400
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")
            return jsonify({'error': 'An unexpected error occurred'}), 500
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
            
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['POST'])
@login_required
@rate_limit(requests_per_minute=30)
@handle_errors
def detect_deepfake():
   
    if request.content_length > 10 * 1024 * 1024:  # 10MB limit
        return jsonify({'error': 'File size exceeds 10MB limit'}), 400
        
 
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    file = request.files.get('image')
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file tychepe. Please upload PNG or JPG images only.'}), 400
    
    if current_user.usage_count >= 5 and not current_user.is_premium:
        return jsonify({'error': 'Free limit reached'}), 403

   
    try:
       
        response = requests.post(
            os.getenv('DEEPWARE_API_URL'),
            headers={'Authorization': f'Bearer {os.getenv("DEEPWARE_API_KEY")}'},
            files={'image': file}
        )
        
        if response.status_code == 200:
            current_user.usage_count += 1
            db.session.commit()
            return jsonify(response.json()), 200
        else:
            return jsonify({'error': 'API request failed'}), response.status_code

    except Exception as e:
        logging.error(f"Detection error: {str(e)}")
        return jsonify({'error': 'Processing failed'}), 500

@app.route('/create-checkout-session', methods=['POST'])
@login_required
@handle_errors
def create_checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=current_user.email,
            payment_method_types=['card'],
            line_items=[{
                'price': os.getenv('STRIPE_PRICE_ID'),
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('success', _external=True),
            cancel_url=url_for('cancel', _external=True),
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 403

@app.route('/webhook', methods=['POST'])
def webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET')
        )

        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            customer_email = session['customer_details']['email']
            user = User.query.filter_by(email=customer_email).first()
            if user:
                user.is_premium = True
                db.session.commit()

        return jsonify({'status': 'success'}), 200
    except Exception as e:
        logging.error(f"Webhook error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.route('/styles.css')
def serve_css():
    return send_from_directory('static', 'styles.css')

@app.route('/script.js')
def serve_js():
    return send_from_directory('static', 'script.js')

@app.route('/success')
@login_required
def success():
    return render_template('success.html')

@app.route('/cancel')
@login_required
def cancel():
    return render_template('cancel.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No file uploaded')
            return redirect(request.url)
            
        file = request.files['photo']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            photo = Photo(filename=filename, user_id=current_user.id)
            db.session.add(photo)
            db.session.commit()
            
            return redirect(url_for('dashboard'))
            
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')

with app.app_context():
    db.create_all()

