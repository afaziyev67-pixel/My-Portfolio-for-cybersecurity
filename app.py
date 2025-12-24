from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from database import Database

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here' 

db = Database()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        hashed_pw = generate_password_hash(password)
        mfa_secret = pyotp.random_base32()
        
        if db.add_user(email, hashed_pw, mfa_secret):
            session['setup_email'] = email
            session['setup_secret'] = mfa_secret
            return redirect(url_for('setup_mfa'))
        else:
            flash("This email already exists!")
            
    return render_template('register.html')

@app.route('/setup-mfa')
def setup_mfa():
    if 'setup_email' not in session:
        return redirect(url_for('register'))
    
    email = session['setup_email']
    secret = session['setup_secret']
    
    otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email, 
        issuer_name="Claude_Service"
    )
    
    return render_template('mfa_setup.html', secret=secret, otpauth_url=otpauth_url)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = db.get_user(email) 

        if user and check_password_hash(user[1], password):
            session['mfa_pending_user'] = email
            return redirect(url_for('verify_mfa'))
        else:
            flash("Invalid email or password!")
            
    return render_template('login.html')

@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'mfa_pending_user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_code = request.form['otp_code']
        email = session['mfa_pending_user']
        
        user = db.get_user(email)
        mfa_secret = user[2]
        
        totp = pyotp.TOTP(mfa_secret)
        if totp.verify(otp_code):
            session.pop('mfa_pending_user', None)
            session['user_email'] = email
            return "Success! You have logged in successfully."
        else:
            flash("Invalid MFA code, please try again.")
            
    return render_template('mfa_verify.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=5050, debug=True)
    
