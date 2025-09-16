import asyncio
import ssl
import sqlite3
import os
import hashlib
import random
import string
from email.parser import BytesParser
from email.policy import default
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

mail_loc = "IHA089_Mail"

def get_db_connection():
    DB_FILE = os.path.join(os.getcwd(), mail_loc, "mail_users.db")
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def verify_user(email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed = hashlib.md5(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE email=? AND password=?", (email, hashed))
    row = cursor.fetchone()
    conn.close()
    return row is not None

def save_mail(sender, recipient, subject, body):
    conn = get_db_connection()
    cursor = conn.cursor()
    unique_key = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    cursor.execute("""
        INSERT INTO mails (reciver_email, sender_email, subject, bodycontent, unique_key)
        VALUES (?, ?, ?, ?, ?)
    """, (recipient, sender, subject, body, unique_key))
    conn.commit()
    conn.close()

class AuthHandler:
    async def handle_DATA(self, server, session, envelope):
        msg = BytesParser(policy=default).parsebytes(envelope.original_content)
        sender = envelope.mail_from
        recipients = envelope.rcpt_tos
        recipients_str = ", ".join(recipients)
        subject = msg['subject'] if msg['subject'] else "(No Subject)"
        body = msg.get_body(preferencelist=('plain',))
        body_content = body.get_content() if body else msg.get_payload()

        save_mail(sender, recipients_str, subject, body_content)
        return "250 Message accepted for delivery"

    async def authenticate(self, server, session, envelope, mechanism, auth_data):
        if mechanism == "LOGIN" and isinstance(auth_data, LoginPassword):
            email = auth_data.login.decode()
            password = auth_data.password.decode()
            if verify_user(email, password):
                return AuthResult(success=True)
            else:
                return AuthResult(success=False)
        return AuthResult(success=False)

    async def auth_LOGIN(self, server, session, envelope, args):
        return await server._call_authenticate(session, envelope, "LOGIN", args)

def build_ssl_context():
    CERT_FILE = os.path.join(os.getcwd(), mail_loc, "server.crt")
    KEY_FILE = os.path.join(os.getcwd(), mail_loc, "server.key")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return context

def run_server():
    ssl_context = build_ssl_context()
    handler = AuthHandler()
    controller = Controller(
        handler,
        hostname="127.0.0.1",
        port=465,
        ssl_context=ssl_context
    )
    controller.start()

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_forever()
    except KeyboardInterrupt:
        controller.stop()


