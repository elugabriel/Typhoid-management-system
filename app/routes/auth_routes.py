# app/routes/auth_routes.py
from flask import render_template, redirect, url_for, flash, request
from app import app, db
from app.models import User, Doctor, Hospital
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app.forms import UserSignUpForm, DoctorSignUpForm, LoginForm

@app.route('/signup/user', methods=['GET', 'POST'])
def signup_user():
    form = UserSignUpForm()
    if form.validate_on_submit():
        user = User(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            dob=form.dob.data,
            gender=form.gender.data,
            marital_status=form.marital_status.data,
            address=form.address.data,
            state=form.state.data,
            password_hash=generate_password_hash(form.password.data)
        )
        db.session.add(user)
        db.session.commit()
        flash('User account created!', 'success')
        return redirect(url_for('login'))
    return render_template('auth/signup_user.html', form=form)

@app.route('/signup/doctor', methods=['GET', 'POST'])
def signup_doctor():
    form = DoctorSignUpForm()
    if form.validate_on_submit():
        doctor = Doctor(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            dob=form.dob.data,
            gender=form.gender.data,
            marital_status=form.marital_status.data,
            address=form.address.data,
            state=form.state.data,
            hospital_id=form.hospital_id.data,
            password_hash=generate_password_hash(form.password.data)
        )
        db.session.add(doctor)
        db.session.commit()
        flash('Doctor account created!', 'success')
        return redirect(url_for('login'))
    return render_template('auth/signup_doctor.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # First, check if it's a User
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('user_dashboard'))

        # Then check if it's a Doctor
        doctor = Doctor.query.filter_by(email=form.email.data).first()
        if doctor and check_password_hash(doctor.password_hash, form.password.data):
            login_user(doctor)
            return redirect(url_for('doctor_dashboard'))

        flash('Invalid credentials', 'danger')
    return render_template('auth/login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
