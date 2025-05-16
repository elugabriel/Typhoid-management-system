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
from flask import session
from datetime import datetime

# === App Config ===

ADMIN_EMAIL = "admin@managementsystem.com"
ADMIN_PASSWORD = "securepassword123"


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
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    dob = db.Column(db.Date)
    gender = db.Column(db.String(10))
    marital_status = db.Column(db.String(20))
    address = db.Column(db.String(200))
    state = db.Column(db.String(50))
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'))
    password = db.Column(db.String(200))  # <-- Add this line

    hospital = db.relationship('Hospital', backref='doctors')
    
    def get_id(self):
        return str(self.id)

    # These come from UserMixin, but include manually if needed:
    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False


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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'))
    status = db.Column(db.String(20), default="Pending")  # Pending, Approved, Rejected
    appointment_date = db.Column(db.Date)
    appointment_time = db.Column(db.Time)

    user = db.relationship('User', backref='consultations')
    doctor = db.relationship('Doctor', backref='consultations')



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

class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class HospitalForm(FlaskForm):
    name = StringField('Hospital Name', validators=[DataRequired(), Length(max=100)])
    state = StringField('State', validators=[DataRequired(), Length(max=50)])
    address = StringField('Address', validators=[Length(max=200)])
    phone = StringField('Phone', validators=[Length(max=15)])  
    submit = SubmitField('Create Hospital')

class EditDoctorForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    dob = DateField('Date of Birth', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female')], validators=[DataRequired()])
    marital_status = SelectField('Marital Status', choices=[('Single', 'Single'), ('Married', 'Married')], validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    password = PasswordField('Password')  # Optional for updates
    hospital_id = SelectField('Hospital', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Update')
    
class DoctorLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
# ===User  ROUTES ===
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
    
    consultations = Consultation.query.filter_by(user_id=current_user.id).order_by(Consultation.appointment_date.desc()).all()
    return render_template('user_dashboard.html', user=current_user,  consultations=consultations)


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

    # Fetch doctors in the same state
    doctors_in_state = Doctor.query.filter_by(state=user_state).all()

    # Populate doctor choices in the form
    form.doctor_id.choices = [(doctor.id, doctor.name) for doctor in doctors_in_state]

    # Pre-fill the form with user's details on GET request
    if request.method == 'GET':
        form.name.data = current_user.name
        form.phone.data = current_user.phone
        form.dob.data = current_user.dob
        form.gender.data = current_user.gender
        form.marital_status.data = current_user.marital_status
        form.address.data = current_user.address
        form.state.data = current_user.state

    # Handle form submission
    if form.validate_on_submit():
        consultation = Consultation(
            user_id=current_user.id,
            doctor_id=form.doctor_id.data,
            status="Pending",
            appointment_date=datetime.utcnow().date(),
            appointment_time=datetime.utcnow().time()
        )
        db.session.add(consultation)
        db.session.commit()
        flash('Your consultation has been booked and is pending approval.', 'success')
        return redirect(url_for('consultation_details', consultation_id=consultation.id))

    return render_template('user_consultations.html', form=form, user=current_user)

@app.route('/consultation/<int:consultation_id>')
@login_required
def consultation_details(consultation_id):
    consultation = Consultation.query.get_or_404(consultation_id)

    if consultation.user_id != current_user.id:
        abort(403)  # Forbidden if user tries to access someone else's record

    return render_template('consultation_details.html', consultation=consultation)

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

# ======== Admin section ========

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    # Query the required data
    total_users = User.query.count()
    total_doctors = Doctor.query.count()
    total_assessments = SymptomAssessment.query.count()
    total_bookings = Consultation.query.count() if 'Consultation' in globals() else 0
    users = User.query.all()
    doctors = Doctor.query.all()

    # Pass all required data to the template
    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        total_doctors=total_doctors,
        total_assessments=total_assessments,
        total_bookings=total_bookings,
        users=users,
        doctors=doctors
    )


# ADMIN_EMAIL = "admin@managementsystem.com"
# ADMIN_PASSWORD = "securepassword123"

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        if form.email.data == ADMIN_EMAIL and form.password.data == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'danger')
    return render_template('admin_login.html', form=form)  



from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Admin login required.', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/create-hospital', methods=['GET', 'POST'])
def create_hospital():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    form = HospitalForm()
    if form.validate_on_submit():
        new_hospital = Hospital(
            name=form.name.data,
            state=form.state.data,
            address=form.address.data,
            phone=form.phone.data
        )
        db.session.add(new_hospital)
        db.session.commit()
        flash('Hospital created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_hospital.html', form=form)

@app.route('/admin/create-doctor', methods=['GET', 'POST'])
def create_doctor():
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
            password = form.password.data
        )
        # doctor.set_password(form.password.data)  # Assuming Doctor model has set_password()
        db.session.add(doctor)
        db.session.commit()
        flash('Doctor created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_doctor.html', form=form)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# Route to edit doctor
@app.route('/admin/edit_doctor/<int:doctor_id>', methods=['GET', 'POST'])
def edit_doctor(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    form = EditDoctorForm(obj=doctor)

    # Populate the hospital_id choices BEFORE validation
    hospitals = Hospital.query.all()
    form.hospital_id.choices = [(h.id, h.name) for h in hospitals]

    if form.validate_on_submit():
        doctor.name = form.name.data
        doctor.phone = form.phone.data
        doctor.dob = form.dob.data
        doctor.gender = form.gender.data
        doctor.marital_status = form.marital_status.data
        doctor.address = form.address.data
        doctor.state = form.state.data

        if form.password.data:
            doctor.password = form.password.data  # Plain text (note: not recommended for production)

        doctor.hospital_id = form.hospital_id.data

        db.session.commit()
        flash('Doctor updated successfully.')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_doctor.html', form=form)




# Route to delete doctor
@app.route('/admin/delete_doctor/<int:doctor_id>', methods=['POST'])
def delete_doctor(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    db.session.delete(doctor)
    db.session.commit()
    flash('Doctor deleted successfully.')
    return redirect(url_for('admin_dashboard'))

# === Doctor section ===
@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        return user
    return Doctor.query.get(int(user_id))  # fallback

@app.route('/doctor-login', methods=['GET', 'POST'])
def doctor_login():
    form = DoctorLoginForm()
    if form.validate_on_submit():
        doctor = Doctor.query.filter_by(email=form.email.data).first()
        if doctor and doctor.password == form.password.data:
            session['doctor'] = doctor.id  # manually manage session
            return redirect(url_for('doctor_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('doctor_login.html', form=form)



@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'doctor' not in session:
        return redirect(url_for('doctor_login'))
    
    doctor = Doctor.query.get(session['doctor'])
    consultations = Consultation.query.filter_by(doctor_id=doctor.id).all()
    
    return render_template('doctor_dashboard.html', doctor=doctor, consultations=consultations)




@app.route('/approve/<int:consultation_id>')
@login_required
def approve_appointment(consultation_id):
    consultation = Consultation.query.get_or_404(consultation_id)

    if not isinstance(current_user, Doctor) or consultation.doctor_id != current_user.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('doctor_dashboard'))

    consultation.status = "Approved"
    db.session.commit()
    flash("Appointment approved.", "success")
    return redirect(url_for('doctor_dashboard'))

@app.route('/reject/<int:consultation_id>')
@login_required
def reject_appointment(consultation_id):
    consultation = Consultation.query.get_or_404(consultation_id)

    if not isinstance(current_user, Doctor) or consultation.doctor_id != current_user.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('doctor_dashboard'))

    consultation.status = "Rejected"
    db.session.commit()
    flash("Appointment rejected.", "warning")
    return redirect(url_for('doctor_dashboard'))


# === MAIN ===
if __name__ == '__main__':
    app.run(debug=True)
