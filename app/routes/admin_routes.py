# app/routes/admin_routes.py
from flask import render_template
from app import app
from flask_login import login_required

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin/dashboard.html')
