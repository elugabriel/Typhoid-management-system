from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, DateField, PasswordField
from wtforms.validators import DataRequired, Length, Email
from flask_login import UserMixin
import os
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import random 

# === App Config ===


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///typhoid.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# === MODELS ===
class User(db.Model, UserMixin):  # Patient
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    marital_status = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.name}>'

class Hospital(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(15), nullable=True)

    def __repr__(self):
        return f'<Hospital {self.name}>'

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    marital_status = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    state = db.Column(db.String(50), nullable=False)  # This field links doctors to their state
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    hospital = db.relationship('Hospital', backref=db.backref('doctors', lazy=True))

    def __repr__(self):
        return f'<Doctor {self.name}>'


    def __repr__(self):
        return f'<Doctor {self.name}>'
    
class SymptomAssessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, default=db.func.now())
    symptoms = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(200), nullable=False)

    user = db.relationship('User', backref=db.backref('assessments', lazy=True))

class Consultation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    consultation_date = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship('User', backref=db.backref('consultations', lazy=True))
    doctor = db.relationship('Doctor', backref=db.backref('consultations', lazy=True))

    def __repr__(self):
        return f'<Consultation {self.id}>'


# === FORMS ===
class UserSignUpForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    dob = DateField('Date of Birth', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female')], validators=[DataRequired()])
    marital_status = SelectField('Marital Status', choices=[('Single', 'Single'), ('Married', 'Married')], validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Sign Up as Patient')

class DoctorSignUpForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    dob = DateField('Date of Birth', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female')], validators=[DataRequired()])
    marital_status = SelectField('Marital Status', choices=[('Single', 'Single'), ('Married', 'Married')], validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    hospital_id = StringField('Hospital ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Sign Up as Doctor')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class UpdateProfileForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    dob = DateField('Date of Birth', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female')], validators=[DataRequired()])
    marital_status = SelectField('Marital Status', choices=[('Single', 'Single'), ('Married', 'Married')], validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    submit = SubmitField('Update Profile')

class ConsultationBookingForm(FlaskForm):
    name = StringField('Patient Name', validators=[DataRequired()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    dob = DateField('Date of Birth', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female')], validators=[DataRequired()])
    marital_status = SelectField('Marital Status', choices=[('Single', 'Single'), ('Married', 'Married')], validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    doctor_id = SelectField('Select Doctor', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Book Consultation')

    
# === ROUTES ===
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup/user', methods=['GET', 'POST'])
def signup_user():
    form = UserSignUpForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            name=form.name.data,
            phone=form.phone.data,
            dob=form.dob.data,
            gender=form.gender.data,
            marital_status=form.marital_status.data,
            address=form.address.data,
            state=form.state.data,
            email=form.email.data,
            password_hash=hashed_password  # Hash the password here
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful!', 'success')
        return redirect(url_for('user_login'))
    return render_template('user_signup.html', form=form)


# Setup Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def user_login():  # <-- Changed name here
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)  # Now refers correctly to flask_login.login_user
            flash('Login successful!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Login failed. Check your email and/or password.', 'danger')
    
    return render_template('user_login.html', form=form)



@app.route('/dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html', user=current_user)


@app.route('/update-profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    form = UpdateProfileForm(obj=current_user)  # Pre-fill with current user data

    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.phone = form.phone.data
        current_user.dob = form.dob.data
        current_user.gender = form.gender.data
        current_user.marital_status = form.marital_status.data
        current_user.address = form.address.data
        current_user.state = form.state.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('update_profile.html', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/symptom-assessment')
@login_required
def symptom_assessment():
    assessments = SymptomAssessment.query.filter_by(user_id=current_user.id).order_by(SymptomAssessment.date.desc()).all()
    return render_template('user_assessment.html', assessments=assessments, user=current_user)



@app.route('/book-consultation', methods=['GET', 'POST'])
@login_required
def book_consultation():
    form = ConsultationBookingForm()

    # Fetch the current user's state
    user_state = current_user.state

    # Fetch doctors based on the user's state
    doctors_in_state = Doctor.query.filter_by(state=user_state).all()

    # Update the doctor selection choices based on the doctors in the user's state
    form.doctor_id.choices = [(doctor.id, doctor.name) for doctor in doctors_in_state]

    # Pre-fill the form with the patient's details
    if request.method == 'GET':  # On GET request, pre-fill the form
        form.name.data = current_user.name
        form.phone.data = current_user.phone
        form.dob.data = current_user.dob
        form.gender.data = current_user.gender
        form.marital_status.data = current_user.marital_status
        form.address.data = current_user.address
        form.state.data = current_user.state

    if form.validate_on_submit():
        # Automatically assign doctor based on the selected doctor_id
        consultation = Consultation(
            user_id=current_user.id,
            doctor_id=form.doctor_id.data,  # Get the doctor from the form
            status="Pending"  # Default status is Pending
        )
        db.session.add(consultation)
        db.session.commit()
        flash('Your consultation has been booked and is pending approval.', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('user_consultations.html', form=form, user=current_user)


#======= Expert System Part ========
SYMPTOM_RULES = {
    # High-weight symptoms (strong indicators of typhoid)
    'Fever': 2,
    'Abdominal pain': 2,
    'Rash': 2,

    # Medium-weight symptoms (moderate indicators)
    'Headache': 1,
    'Loss of appetite': 1,
    'Diarrhea': 1,
    'Constipation': 1,
    'Fatigue': 1,

    # Low-weight or general symptoms (minimal or no impact)
    'Cough': 0,
    'Sneezing': 0,
    'Runny nose': 0,
    'Sore throat': 0,
    'Mild body aches': 0,
    'Itchy eyes': 0,
    'Dizziness': 0,
    'Nausea': 1,
    'Joint pain': 0
}


@app.route('/new-assessment', methods=['GET', 'POST'])
@login_required
def new_assessment():
    if request.method == 'POST':
        selected_symptoms = request.form.getlist('symptoms')
        total_score = sum(SYMPTOM_RULES.get(symptom, 0) for symptom in selected_symptoms)

        if total_score >= 5:
            result = 'High likelihood of typhoid. Please consult a doctor.'
        elif 3 <= total_score < 5:
            result = 'Moderate symptoms. Monitor closely and seek medical advice if symptoms persist.'
        else:
            result = 'Low likelihood of typhoid.'

        new_assess = SymptomAssessment(
            user_id=current_user.id,
            symptoms=', '.join(selected_symptoms),
            result=result
        )
        db.session.add(new_assess)
        db.session.commit()

        flash('Assessment submitted!', 'success')
        return redirect(url_for('symptom_assessment'))

    # Shuffle symptom list before rendering
    symptoms = list(SYMPTOM_RULES.keys())
    random.shuffle(symptoms)
    return render_template('new_assessment.html', symptoms=[{'name': s} for s in symptoms])

@app.route('/health-tips')
@login_required
def health_tips():
    tips = [
        "Stay hydrated by drinking at least 8 cups of water daily.",
        "Exercise for at least 30 minutes every day.",
        "Eat a balanced diet rich in fruits and vegetables.",
        "Get at least 7-8 hours of quality sleep each night.",
        "Take regular breaks during screen time to reduce eye strain.",
        "Practice mindfulness or meditation to manage stress.",
        "Wash your hands regularly to prevent infections.",
    ]
    return render_template('health_tips.html', tips=tips)

# === MAIN ===
if __name__ == '__main__':
    app.run(debug=True)
