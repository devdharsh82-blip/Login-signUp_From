from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        gender = request.form['gender']
        dob = request.form['dob']
        current_class = request.form['current_class']


        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('''
                INSERT INTO users (username, email, password)
                VALUES (?, ?, ?)
            ''', (f"{first_name} {last_name}", email, hashed_password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id, username, password FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
