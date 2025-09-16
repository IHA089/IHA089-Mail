from flask import Flask, request, make_response, render_template, session, jsonify, redirect, url_for
from functools import wraps
import jwt as pyjwt
import sqlite3, datetime, uuid, hashlib, logging, os, random, string

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

MailServerIHA089 = Flask(__name__)
MailServerIHA089.secret_key = "vulnerable_lab_by_IHA089"

JWT_SECRET = "MoneyIsPower"

mail_loc = "IHA089_Mail"

def generate_random_text(length=20):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))

def create_database():
    db_path = os.path.join(os.getcwd(), mail_loc, "mail_users.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        uuid TEXT NOT NULL
    )
    ''')
    password="Admin@#$12"
    hash_password = hashlib.md5(password.encode()).hexdigest()
    user_uuid = str(uuid.uuid4())
    query = "INSERT INTO users (username, email, password, uuid) VALUES ('Admin', 'admin@iha089.org', '"+hash_password+"', '"+user_uuid+"')"

    cursor.execute(query)

    cursor.execute('''
    CREATE TABLE mails (
        id INT AUTO_INCREMENT PRIMARY KEY,
        reciver_email VARCHAR(255) NOT NULL,
        sender_email VARCHAR(255) NOT NULL,
        subject VARCHAR(255),
        bodycontent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'unread',
        unique_key VARCHAR(20) NOT NULL
    )
    ''')

    conn.commit()
    conn.close()

def check_database():
    db_path = os.path.join(os.getcwd(), mail_loc, "mail_users.db")
   
    if not os.path.isfile(db_path):
        create_database()

check_database()

def get_db_connection():
    db_path = os.path.join(os.getcwd(), mail_loc, "mail_users.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_username_by_uuid(user_uuid):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE uuid = ?", (user_uuid,))
    row = cursor.fetchone()
    conn.close()
    return row['email'] if row else None

def get_uuid_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT uuid FROM users WHERE email = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row['uuid'] if row else None

def check_cookies():
    user_uuid = request.cookies.get("uuid")

    username = get_username_by_uuid(user_uuid)
    if username:
        session['user'] = username
        return True
    else:
        return False

def get_email_data(email):
    db_path = os.path.join(os.getcwd(), mail_loc, "mail_users.db")
    conn = sqlite3.connect(db_path)  
    cursor = conn.cursor()
    query = "SELECT id, reciver_email, sender_email, subject, bodycontent, timestamp, status, unique_key FROM mails WHERE reciver_email = '"+email+"'"
    cursor.execute(query)
    emails = cursor.fetchall()
    conn.close()
    return emails


@MailServerIHA089.route('/')
@MailServerIHA089.route('/index')
def home():
    if not check_cookies():
        session.clear()
    return render_template('index.html', user=session.get('user'))

@MailServerIHA089.route('/index.html')
def home_():
    if not check_cookies():
        session.clear()
    return render_template('index.html', user=session.get('user'))

@MailServerIHA089.route('/login.html')
def login_html():
    if not check_cookies():
        session.clear()
    return render_template('login.html')

@MailServerIHA089.route('/join.html')
def join_html():
    if not check_cookies():
        session.clear()
    return render_template('join.html')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:  
            return redirect(url_for('login_html', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@MailServerIHA089.route('/mark-as-read', methods=['POST'])
def mark_as_read():
    data = request.get_json()
    unique_key = data.get('unique_key')
    if not unique_key:
        return jsonify({'error':'unique key is required'}), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE mails SET status = 'read ' WHERE unique_key = ?", (unique_key,))
        conn.commit()
        conn.close()
        return jsonify({'message':'success'})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

@MailServerIHA089.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user_uuid = request.cookies.get("uuid")

        username = get_username_by_uuid(user_uuid)
        if username:
            session['user'] = username
            return redirect(url_for('dashboard'))

        return render_template('login.html')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username is None or password is None:
            error_message = "Please provide both username and password."
            return render_template('login.html', error=error_message)

        hash_password = hashlib.md5(password.encode()).hexdigest()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (username, hash_password))
        user = cursor.fetchone()
        conn.close()

    if user:
        session['user'] = username
        user_uuid = get_uuid_by_username(username)
        if user_uuid is None:
            error_message = "Invalid username or password. Please try again."
            return render_template('login.html', error=error_message)

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie("uuid", user_uuid, httponly=True, samesite="Strict")  
        return response
        
    error_message = "Invalid username or password. Please try again."
    return render_template('login.html', error=error_message)

@MailServerIHA089.route('/join', methods=['GET', 'POST'])
def join():
    if not check_cookies():
        session.clear()
    if 'user' in session:
        return render_template('dashboard.html', user=session.get('user'))
    email = request.form.get('email')
    username = request.form.get('fullname')
    password = request.form.get('password')
    if not email.endswith('@iha089.org'):
        error_message = "Only email with @iha089.org domain is allowed."
        return render_template('join.html', error=error_message)
    hash_password = hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users where email = ?", (email,))
    if cursor.fetchone():
        error_message = "Email already taken. Please choose another."
        conn.close()
        return render_template('join.html', error=error_message)
    else:
        try:
            user_uuid = str(uuid.uuid4())

            cursor.execute("INSERT INTO users (username, email, password, uuid) VALUES (?, ?, ?, ?)", (username, email, hash_password, user_uuid))
            conn.commit()
            response = make_response(render_template('login.html'))
            response.set_cookie("uuid", user_uuid, httponly=True, samesite="Strict")  
            return response
        except sqlite3.Error as err:
            error_message = "Something went wrong, Please try again later."
            return render_template('join.html', error=error_message)
        conn.close()

@MailServerIHA089.route('/delete_user', methods=['GET', 'POST'])
def delete_user():
    email = request.args.get('email')
    key = request.args.get('key')
    if key != "dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275":
        return jsonify({"message": "something went wrong"}), 500
    if not email:
        return jsonify({"message": "something went wrong"}), 500
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        return jsonify({"message": "something went wrong"}), 500   

@MailServerIHA089.route('/dashboard')
@MailServerIHA089.route("/dashboard.html")
@login_required
def dashboard():
    if not check_cookies():
        session.clear()
    if 'user' not in session:
        return redirect(url_for('login_html'))

    email_data = get_email_data(session.get('user'))
    email_data = email_data[::-1]

    return render_template('dashboard.html', user=session.get('user'), emails=email_data)

@MailServerIHA089.route('/logout')
@MailServerIHA089.route('/logout.html')
def logout():
    session.clear() 
    response = make_response(redirect(url_for('login_html')))
    response.set_cookie("uuid", "", httponly=True, samesite="Strict")
    return response

@MailServerIHA089.after_request
def add_cache_control_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
