import os
from flask import Flask, redirect, url_for, session, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.consumer import oauth_error, oauth_authorized
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or os.urandom(24)

mysql_user = os.getenv('MYSQL_USER', 'root')
mysql_pass = os.getenv('MYSQL_PASSWORD', '')
mysql_host = os.getenv('MYSQL_HOST', '127.0.0.1')
mysql_port = os.getenv('MYSQL_PORT', '3306')
mysql_db   = os.getenv('MYSQL_DB', 'oauth_db')

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{mysql_user}:{mysql_pass}@{mysql_host}:{mysql_port}/{mysql_db}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    github_id = db.Column(db.String(50), unique=True, nullable=True)
    auth_method = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Prevent caching of protected pages
@app.after_request
def set_secure_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

# GitHub OAuth blueprint
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
github_bp = make_github_blueprint(
    client_id=os.getenv("GITHUB_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
    scope="read:user",
    redirect_url="/"
)
app.register_blueprint(github_bp, url_prefix="/login")

# OAuth error handler
@oauth_error.connect_via(github_bp)
def github_oauth_error(blueprint, message, response):
    flash("GitHub login failed. Please try again.", 'danger')
    return redirect(url_for('login'))

# OAuth success handler
@oauth_authorized.connect_via(github_bp)
def github_logged_in(blueprint, token):
    if not token:
        flash("GitHub token missing, authorization failed.", 'danger')
        return False
    resp = blueprint.session.get("/user")
    if not resp.ok:
        flash("Failed fetching GitHub user info.", 'danger')
        return False
    info = resp.json()
    user = User.query.filter_by(github_id=str(info.get('id'))).first()
    if not user:
        user = User.query.filter_by(email=info.get('email')).first()
        if user:
            user.github_id = str(info.get('id'))
            user.auth_method = 'github'
            db.session.commit()
        else:
            user = User(
                username=info.get('login'),
                email=info.get('email') or f"{info.get('id')}@github",
                github_id=str(info.get('id')),
                auth_method='github'
            )
            db.session.add(user)
            db.session.commit()
    login_user(user)
    db.session.add(LoginLog(user_id=user.id, ip_address=request.remote_addr))
    db.session.commit()
    return redirect(url_for('home'))


# Routes for manual signup/login
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter((User.username==username)|(User.email==email)).first():
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('signup'))
        # TODO: validate password policy
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=pw_hash, auth_method='manual')
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        ident = request.form['email']
        password = request.form['password']
        remember = 'remember' in request.form
        user = User.query.filter((User.email==ident)|(User.username==ident)).first()
        if user and user.auth_method == 'manual' and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            db.session.add(LoginLog(user_id=user.id, ip_address=request.remote_addr))
            db.session.commit()
            return redirect(url_for('home'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('home.html', username=current_user.username)

@app.route("/profile")
@login_required
def profile():
    print("GitHub authorized:", github.authorized)
    if github.authorized:
        resp = github.get("/user")
        if not resp.ok:
            flash("Failed to fetch GitHub profile.", "danger")
            session.clear()
            return redirect(url_for("home"))
        user_info = resp.json()
        print(user_info)
        return render_template("profile.html", user=user_info, github_profile_url=user_info.get("html_url"))
    else:
        # Fall back to DB user info
        return render_template(
            "profile.html",
            user=current_user,
            github_profile_url="https://github.com/" + current_user.username if current_user.auth_method == "github" else None
        )




@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
