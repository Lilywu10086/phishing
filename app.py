#importing required libraries

from flask import Flask, request, render_template, flash, redirect, url_for, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
import os
from datetime import datetime
import threading
import time
warnings.filterwarnings('ignore')
from feature import FeatureExtraction
from models import db, User, DetectionHistory
from forms import LoginForm, RegistrationForm, BatchDetectionForm
from api import api
from sandbox import get_sandbox

# Load model
file = open("pickle/model.pkl","rb")
gbc = pickle.load(file)
file.close()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Please change to a random string
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_detection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Register API blueprint
app.register_blueprint(api, url_prefix='/api')

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        
        # Sandbox isolation
        sandbox = get_sandbox()
        sandbox_result = sandbox.safe_url_access(url)
        
        # Continue with AI detection
        obj = FeatureExtraction(url, sandbox_data=sandbox_result.get('sandbox_data', {}))
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        
        # Save detection history (if user is logged in)
        if current_user.is_authenticated:
            detection = DetectionHistory(
                user_id=current_user.id,
                url=url,
                is_safe=(y_pro_non_phishing >= 0.5),
                confidence_score=y_pro_non_phishing,
                sandbox_risk_level=sandbox_result.get('risk_level', 'unknown')
            )
            db.session.add(detection)
            db.session.commit()
        
        return render_template('index.html', 
                             xx=round(y_pro_non_phishing,2), 
                             url=url,
                             sandbox_result=sandbox_result,
                             sandbox_report=sandbox.get_sandbox_report(sandbox_result))
    
    return render_template("index.html", xx=-1)

@app.route("/batch", methods=["GET", "POST"])
def batch_detection():
    form = BatchDetectionForm()
    results = []
    
    if form.validate_on_submit():
        urls_text = form.urls_text.data.strip()
        urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
        
        if len(urls) > 50:
            flash('Maximum 50 URLs can be detected at once', 'error')
            return render_template('batch_detection.html', form=form)
        
        # Batch detection
        for i, url in enumerate(urls):
            try:
                obj = FeatureExtraction(url)
                x = np.array(obj.getFeaturesList()).reshape(1,30)
                
                y_pred = gbc.predict(x)[0]
                y_pro_phishing = gbc.predict_proba(x)[0,0]
                y_pro_non_phishing = gbc.predict_proba(x)[0,1]
                
                result = {
                    'url': url,
                    'is_safe': bool(y_pro_non_phishing >= 0.5),
                    'confidence_score': float(y_pro_non_phishing),
                    'detected_at': datetime.utcnow().isoformat()
                }
                
                # Save detection history (if user is logged in)
                if current_user.is_authenticated:
                    detection = DetectionHistory(
                        user_id=current_user.id,
                        url=url,
                        is_safe=bool(y_pro_non_phishing >= 0.5),
                        confidence_score=float(y_pro_non_phishing)
                    )
                    db.session.add(detection)
                
                results.append(result)
                
                # Add small delay to avoid too fast requests
                time.sleep(0.1)
                
            except Exception as e:
                result = {
                    'url': url,
                    'is_safe': False,
                    'confidence_score': 0.0,
                    'detected_at': datetime.utcnow().isoformat(),
                    'error': str(e)
                }
                results.append(result)
        
        # Commit all detection history
        if current_user.is_authenticated:
            db.session.commit()
        
        flash(f'Batch detection completed! Detected {len(results)} URLs', 'success')
        return render_template('batch_detection.html', form=form, results=results)
    
    return render_template('batch_detection.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            # Update last login time
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route("/profile")
@login_required
def profile():
    # Get user's detection history
    detections = DetectionHistory.query.filter_by(user_id=current_user.id).order_by(DetectionHistory.detected_at.desc()).limit(10).all()
    
    # Calculate statistics
    total_detections = DetectionHistory.query.filter_by(user_id=current_user.id).count()
    safe_count = DetectionHistory.query.filter_by(user_id=current_user.id, is_safe=True).count()
    unsafe_count = DetectionHistory.query.filter_by(user_id=current_user.id, is_safe=False).count()
    
    return render_template('profile.html', 
                         detections=detections,
                         total_detections=total_detections,
                         safe_count=safe_count,
                         unsafe_count=unsafe_count)

# Create database tables
def create_tables():
    with app.app_context():
        db.create_all()
        print("Database tables created")

if __name__ == "__main__":
    create_tables()
    app.run(debug=True)