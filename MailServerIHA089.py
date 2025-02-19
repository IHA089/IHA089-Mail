from flask import Flask, request, render_template, session, jsonify, redirect, url_for
from functools import wraps
import sqlite3
import hashlib
import logging
import os

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

MailServerIHA089 = Flask(__name__)

mail_loc = "/IHA089-Mail/"

def create_database():
    conn = sqlite3.connect('mail_users.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE mail_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    password="Admin@#$12"
    hash_password = hashlib.md5(password.encode()).hexdigest()
    query = "INSERT INTO mail_users (username, email, password) VALUES ('Admin', 'admin@iha089.org', '"+hash_password+"')"

    cursor.execute(query)

    cursor.execute('''
    CREATE TABLE Email_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        sender VARCHAR(255) NOT NULL,
        subject VARCHAR(255),
        bodycontent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    #cursor.execute("INSERT INTO Email_data(email, sender, subject, bodycontent) VALUES ('test@iha089.org.in', 'IHA089', 'verify your account', '<h2>Verify Your Account</h2><p>Click the button below to verify your email address:</p><a href=\"https://example.com/verify?token=YOUR_TOKEN\">Verify Your Account</a><p>If you did not request this, please ignore this email.</p>')")
    conn.commit()
    conn.close()

def check_database():
    db_path = os.getcwd()+mail_loc+'mail_users.db'
    if not os.path.isfile(db_path):
        create_database()


check_database()

def get_db_connection():
    db_path = os.getcwd()+mail_loc+'mail_users.db'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def get_email_data(email):
    db_path = os.getcwd()+mail_loc+'mail_users.db'
    conn = sqlite3.connect(db_path)  
    cursor = conn.cursor()
    query = "SELECT id, email, sender, subject, bodycontent, timestamp FROM Email_data WHERE email = '"+email+"'"
    cursor.execute(query)
    emails = cursor.fetchall()
    conn.close()
    return emails


@MailServerIHA089.route('/')
def home():
    return render_template('index.html', user=session.get('user'))

@MailServerIHA089.route('/index.html')
def home_():
    return render_template('index.html', user=session.get('user'))

@MailServerIHA089.route('/login.html')
def login_html():
    return render_template('login.html')

@MailServerIHA089.route('/join.html')
def join_html():
    return render_template('join.html')

@MailServerIHA089.route('/acceptable.html')
def acceptable_html():
    return render_template('acceptable.html', user=session.get('user'))

@MailServerIHA089.route('/term.html')
def term_html():
    return render_template('term.html', user=session.get('user'))

@MailServerIHA089.route('/privacy.html')
def privacy_html():
    return render_template('privacy.html', user=session.get('user'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:  
            return redirect(url_for('login_html', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@MailServerIHA089.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    hash_password = hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM mail_users WHERE email = ? AND password = ?", (username, hash_password))
    user = cursor.fetchone()
    conn.close()

    if user:
        session['user'] = username
        return redirect(url_for('dashboard'))
    error_message = "Invalid username or password. Please try again."
    return render_template('login.html', error=error_message)

@MailServerIHA089.route('/join', methods=['POST'])
def join():
    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')
    hash_password = hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    query = f"INSERT INTO mail_users (username, email, password) VALUES ('{username}', '{email}', '{hash_password}')".format(email, username, hash_password)
    cursor.execute("SELECT * FROM mail_users where email = ?", (email,))
    if cursor.fetchone():
        error_message = "Email already taken. Please choose another."
        conn.close()
        return render_template('join.html', error=error_message)
    else:
        try:
            cursor.execute(query)
            conn.commit()
            return render_template('login.html')
        except sqlite3.Error as err:
            error_message = "Something went wrong, Please try again later."
            return render_template('join.html', error=error_message)
        conn.close()
    
@MailServerIHA089.route('/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275', methods=['POST'])   
def dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275():
    try:
        data = request.get_json()

        email = data.get('email')
        sender = data.get('sender')
        subject = data.get('subject')
        bodycontent = data.get('bodycontent')

        if not email or not sender or not subject or not bodycontent:
            return jsonify({"error": "Invalid request"}), 400
        # print(f"email: {email}")
        # print(f"sender: {sender}")
        # print(f"subject: {subject}")
        # print(f"bodycontent:{bodycontent}")
        query = f"INSERT INTO Email_data (email, sender, subject, bodycontent) VALUES ('{email}', '{sender}', '{subject}', '{bodycontent}')".format(email, sender, subject, bodycontent)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        return jsonify({"message": "success"}), 200

    except Exception as e:
        return jsonify({"error": "An error occurred"}), 500

@MailServerIHA089.route('/dashboard')
@MailServerIHA089.route("/dashboard.html")
@login_required
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login_html'))
    admin_list=['admin', 'administrator']
    if session.get('user') in admin_list:
        return render_template('admin-dashboard.html', user=session.get('user'))

    email_data = get_email_data(session.get('user'))
    email_data = email_data[::-1]

    return render_template('dashboard.html', user=session.get('user'), emails=email_data)

@MailServerIHA089.route('/logout.html')
def logout():
    session.clear() 
    return redirect(url_for('login_html'))

@MailServerIHA089.after_request
def add_cache_control_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response