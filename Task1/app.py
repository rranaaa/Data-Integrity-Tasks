from flask import Flask, request, jsonify, send_file
from flask_mysqldb import MySQL
import bcrypt
import pyotp
import qrcode
import io
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'auth_api'

mysql = MySQL(app)

# JWT Configuration
app.config["JWT_SECRET_KEY"] = "your_jwt_secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=10)
jwt = JWTManager(app)

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    existing_user = cur.fetchone()

    if existing_user:
        cur.close()
        return jsonify({"message": "Username already exists"}), 409

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "User registered successfully"}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "All fields are required"}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, password FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    if not user or not bcrypt.checkpw(password.encode(), user[1].encode()):
        return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful, scan QR code for 2FA"}), 200

# Generate QR Code for 2FA
@app.route('/generate-2fa/<username>', methods=['GET'])
def generate_2fa(username):
    secret = pyotp.random_base32()
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET twofa_secret = %s WHERE username = %s", (secret, username))
    mysql.connection.commit()
    cur.close()

    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureApp")
    qr = qrcode.make(otp_uri)
    img = io.BytesIO()
    qr.save(img, format="PNG")
    img.seek(0)

    return send_file(img, mimetype='image/png')

# Verify 2FA
@app.route('/verify-2fa/<username>', methods=['POST'])
def verify_2fa(username):
    data = request.json
    otp = data.get('otp')

    if not otp:
        return jsonify({"message": "OTP code is required"}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({"message": "User not found or 2FA not set up"}), 404

    totp = pyotp.TOTP(user[0])
    if totp.verify(otp):
        access_token = create_access_token(identity=username)
        return jsonify({"message": "2FA verified successfully", "access_token": access_token}), 200
    else:
        return jsonify({"message": "Invalid or expired 2FA code"}), 401

# CRUD Operations for Products
@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    data = request.json
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    quantity = data.get('quantity')

    if not name or not price or not quantity:
        return jsonify({"message": "Missing required fields"}), 400

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                (name, description, price, quantity))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Product added successfully"}), 201

@app.route('/products', methods=['GET'])
def get_products():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    cur.close()

    return jsonify(products)

@app.route('/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    data = request.json
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    quantity = data.get('quantity')

    cur = mysql.connection.cursor()
    cur.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                (name, description, price, quantity, product_id))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Product updated successfully"})

@app.route('/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Product deleted successfully"})

if __name__ == '__main__':
    app.run(debug=True)
