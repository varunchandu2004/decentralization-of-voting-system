from flask import Flask, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret_key'
app.config['DATABASE_URI'] = 'jhwdvaskyu'
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id id to be mentioned'), nullable=False)
    candidate = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Initialize Database
@app.before_first_request
def create_tables():
    db.create_all()

# Routes
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('vote.html'))
    return redirect(url_for('user_login.html'))

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user and not user.is_admin:
            session['username'] = username
            return redirect(url_for('vote'))
        else:
            return 'Invalid credentials or admin account'
    return render_template('user_login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password, is_admin=True).first()
        if user:
            session['username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return 'Invalid admin credentials'
    return render_template('admin_login.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'username' not in session:
        return redirect(url_for('user_login'))
    
    if request.method == 'POST':
        candidate = request.form['candidate']
        user = User.query.filter_by(username=session['username']).first()
        if user:
            new_vote = Vote(user_id=user.id, candidate=candidate)
            db.session.add(new_vote)
            db.session.commit()
            return 'Vote submitted successfully'
    return render_template('vote.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session:
        return redirect(url_for('admin_login'))
    
    admin = User.query.filter_by(username=session['username'], is_admin=True).first()
    if not admin:
        return 'Access denied'
    
    votes_count = Vote.query.with_entities(Vote.candidate, db.func.count(Vote.id)).group_by(Vote.candidate).all()
    return render_template('admin_dashboard.html', votes_count=votes_count)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
