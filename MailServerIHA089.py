from flask import Flask, request, make_response, render_template, session, jsonify, redirect, url_for
from functools import wraps
import jwt as pyjwt
import check_module
import sqlite3, datetime, uuid, hashlib, logging, os

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

MailServerIHA089 = Flask(__name__)
MailServerIHA089.secret_key = "vulnerable_lab_by_IHA089"

JWT_SECRET = "MoneyIsPower"

mail_loc = "IHA089-Mail"

user_data = {}

def create_database():
    db_path = os.path.join(os.getcwd(), mail_loc, "mail_users.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE mail_users (
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
    query = "INSERT INTO mail_users (username, email, password, uuid) VALUES ('Admin', 'admin@iha089.org', '"+hash_password+"', '"+user_uuid+"')"

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

    conn.commit()
    conn.close()

def check_database():
    db_path = os.path.join(os.getcwd(), mail_loc, "mail_users.db")
   
    if not os.path.isfile(db_path):
        create_database()

check_database()

if not check_module.install_each_module():
    sys.exit(1)

def get_db_connection():
    db_path = os.path.join(os.getcwd(), mail_loc, "mail_users.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def check_cookies():
    user_uuid = request.cookies.get("uuid")
    jwt_token = request.cookies.get("jwt_token")

    if user_uuid in user_data and jwt_token == user_data[user_uuid]:
        decoded = pyjwt.decode(jwt_token, JWT_SECRET, algorithms="HS256")
        session['user'] = decoded['username']
        return True
    else:
        return False

def get_email_data(email):
    db_path = os.path.join(os.getcwd(), mail_loc, "mail_users.db")
    conn = sqlite3.connect(db_path)  
    cursor = conn.cursor()
    query = "SELECT id, email, sender, subject, bodycontent, timestamp FROM Email_data WHERE email = '"+email+"'"
    cursor.execute(query)
    emails = cursor.fetchall()
    conn.close()
    return emails


@MailServerIHA089.route('/')
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

@MailServerIHA089.route('/acceptable.html')
def acceptable_html():
    if not check_cookies():
        session.clear()
    return render_template('acceptable.html', user=session.get('user'))

@MailServerIHA089.route('/term.html')
def term_html():
    if not check_cookies():
        session.clear()
    return render_template('term.html', user=session.get('user'))

@MailServerIHA089.route('/privacy.html')
def privacy_html():
    if not check_cookies():
        session.clear()
    return render_template('privacy.html', user=session.get('user'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:  
            return redirect(url_for('login_html', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@MailServerIHA089.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user_uuid = request.cookies.get("uuid")
        jwt_token = request.cookies.get("jwt_token")

        if user_uuid in user_data and jwt_token == user_data[user_uuid]:
            decoded = pyjwt.decode(jwt_token, JWT_SECRET, algorithms="HS256")
            session['user'] = decoded['username']
            return redirect(url_for('dashboard'))

        return render_template('login.html')

    username = request.form.get('username')
    password = request.form.get('password')
    hash_password = hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM mail_users WHERE email = ? or username = ? AND password = ?", (username, username, hash_password))
    user = cursor.fetchone()
    conn.close()

    if user:
        session['user'] = username
        user_uuid = user['uuid'] if 'uuid' in user else str(uuid.uuid4())

        jwt_token = pyjwt.encode({
            "username": username,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        user_data[user_uuid] = jwt_token

        if 'uuid' not in user:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE mail_users SET uuid = ? WHERE username = ?", (user_uuid, username))
            conn.commit()
            conn.close()

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie("uuid", user_uuid, httponly=True, samesite="Strict")  
        response.set_cookie("jwt_token", jwt_token, httponly=True, samesite="Strict")
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
    cursor.execute("SELECT * FROM mail_users where email = ?", (email,))
    if cursor.fetchone():
        error_message = "Email already taken. Please choose another."
        conn.close()
        return render_template('join.html', error=error_message)
    else:
        try:
            user_uuid = str(uuid.uuid4())

            cursor.execute("INSERT INTO mail_users (username, email, password, uuid) VALUES (?, ?, ?, ?)", (username, email, hash_password, user_uuid))
            conn.commit()
            response = make_response(render_template('login.html'))
            response.set_cookie("uuid", user_uuid, httponly=True, samesite="Strict")  
            return response
        except sqlite3.Error as err:
            print(err)
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
    if not check_cookies():
        session.clear()
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
    response = make_response(redirect(url_for('login_html')))
    response.set_cookie("uuid", "", httponly=True, samesite="Strict")
    response.set_cookie("jwt_token", "", httponly=True, samesite="Strict")
    return response

@MailServerIHA089.after_request
def add_cache_control_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
