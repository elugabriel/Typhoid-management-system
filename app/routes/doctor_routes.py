# app/routes/doctor_routes.py
from flask import render_template
from app import app
from flask_login import login_required

@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    return render_template('doctor/dashboard.html')
