from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import random
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------------- MAIL CONFIG (FROM RENDER ENV) ----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

mail = Mail(app)

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect('database.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT,
                  age INTEGER,
                  gender TEXT,
                  phone TEXT,
                  email TEXT UNIQUE,
                  password TEXT)''')
    conn.close()

init_db()

# ---------------- HOME ----------------
@app.route('/')
def home():
    return redirect('/login')

# ---------------- SIGNUP ----------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        session['temp_user'] = request.form

        otp = str(random.randint(100000, 999999))
        session['otp'] = otp

        try:
            msg = Message(
                'OTP Verification',
                sender=app.config['MAIL_USERNAME'],
                recipients=[request.form['email']]
            )
            msg.body = f"Your OTP is {otp}"
            mail.send(msg)
        except Exception as e:
            print("Mail Error:", e)
            print("OTP:", otp)

        return redirect('/verify')

    return render_template('signup.html')

# ---------------- OTP VERIFY ----------------
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        if request.form['otp'] == session.get('otp'):
            data = session.get('temp_user')

            hashed_password = generate_password_hash(data['password'])

            try:
                conn = sqlite3.connect('database.db')
                conn.execute("""
                    INSERT INTO users (name, age, gender, phone, email, password)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    data['name'],
                    data['age'],
                    data['gender'],
                    data['phone'],
                    data['email'],
                    hashed_password
                ))
                conn.commit()
                conn.close()

                flash("Signup successful! Please login.")
                return redirect('/login')

            except:
                flash("Email already exists ❌")

        else:
            flash("Wrong OTP ❌")

    return render_template('otp.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        user = conn.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user[6], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            return redirect('/dashboard')
        else:
            flash("Invalid login ❌")

    return render_template('login.html')

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return render_template('dashboard.html', name=session['user_name'])
    return redirect('/login')

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ---------------- FORGOT PASSWORD ----------------
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']

        conn = sqlite3.connect('database.db')
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()

        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_otp'] = otp
            session['reset_email'] = email

            try:
                msg = Message(
                    'Password Reset OTP',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[email]
                )
                msg.body = f"Your OTP is {otp}"
                mail.send(msg)
            except Exception as e:
                print("Mail Error:", e)
                print("RESET OTP:", otp)

            return redirect('/reset_verify')
        else:
            flash("Email not found ❌")

    return render_template('forgot.html')

# ---------------- VERIFY RESET OTP ----------------
@app.route('/reset_verify', methods=['GET', 'POST'])
def reset_verify():
    if request.method == 'POST':
        if request.form['otp'] == session.get('reset_otp'):
            return redirect('/new_password')
        else:
            flash("Invalid OTP ❌")

    return render_template('reset_otp.html')

# ---------------- NEW PASSWORD ----------------
@app.route('/new_password', methods=['GET', 'POST'])
def new_password():
    if request.method == 'POST':
        new_pass = request.form['password']
        hashed = generate_password_hash(new_pass)

        conn = sqlite3.connect('database.db')
        conn.execute(
            "UPDATE users SET password=? WHERE email=?",
            (hashed, session.get('reset_email'))
        )
        conn.commit()
        conn.close()

        flash("Password updated successfully ✅")
        return redirect('/login')

    return render_template('new_password.html')

# ---------------- RUN (RENDER FIX) ----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)