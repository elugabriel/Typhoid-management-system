# app/routes/user_routes.py
from flask import render_template
from app import app
from flask_login import login_required

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    # Placeholder dashboard
    return render_template('user/dashboard.html')
