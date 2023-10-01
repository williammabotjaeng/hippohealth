from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm
from flask_mail import Message, Mail
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField, DateField, DateTimeField
from wtforms.validators import InputRequired, Length, DataRequired, Email
from dotenv import load_dotenv
from datetime import datetime

import moment
import requests
import os



app = Flask(__name__)

load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'QPEunVzlmptwr73MfPz44w=='
api_token = os.getenv("API_TOKEN")
log_config_id = os.getenv("CONFIG_ID")

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")  # Replace with your email address
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD") # Replace with your email password

mail = Mail(app)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    medical_practitioner_type = db.Column(db.String(50))
    medical_authority = db.Column(db.String(50))
    membership_status = db.Column(db.String(20))
    membership_number = db.Column(db.String(20))
    experience = db.Column(db.Integer)

    def __init__(self, username, password, medical_practitioner_type=None, medical_authority=None,
                 membership_status=None, membership_number=None, experience=None):
        self.username = username
        self.password = password
        self.medical_practitioner_type = medical_practitioner_type
        self.medical_authority = medical_authority
        self.membership_status = membership_status
        self.membership_number = membership_number
        self.experience = experience

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    national_id_number = db.Column(db.String(11), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    emergency_contact_name = db.Column(db.String(100), nullable=True)
    emergency_contact_number = db.Column(db.String(15), nullable=True)
    insurance_provider = db.Column(db.String(100), nullable=True)
    insurance_policy_number = db.Column(db.String(50), nullable=True)
    primary_care_physician = db.Column(db.String(100), nullable=True)
    allergies = db.Column(db.String(200), nullable=True)
    medications = db.Column(db.String(200), nullable=True)
    medical_conditions = db.Column(db.String(200), nullable=True)
    surgeries = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('patients', lazy=True))

class Prescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    medication = db.Column(db.String(200), nullable=False)
    dosage = db.Column(db.String(50), nullable=False)
    instructions = db.Column(db.String(200), nullable=True)
    date_prescribed = db.Column(db.Date, nullable=False)
    prescribing_physician = db.Column(db.String(100), nullable=False)

    patient = db.relationship('Patient', backref=db.backref('prescriptions', lazy=True))

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    appointment_type = db.Column(db.String(100), nullable=False)
    notes = db.Column(db.String(200), nullable=True)

    user = db.relationship('User', backref=db.backref('appointments', lazy=True))
    patient = db.relationship('Patient', backref=db.backref('appointments', lazy=True))


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(100))
    actor = db.Column(db.String(100))
    action = db.Column(db.String(100))
    target = db.Column(db.String(100))
    status = db.Column(db.String(100))
    request_time = db.Column(db.String(100))

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=100)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=64)])

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=100)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=64)])
class UserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=2, max=20)])
    password = StringField('Password', validators=[InputRequired(), Length(min=2, max=20)])
    medical_practitioner_type = StringField('Medical Practitioner Type', validators=[Length(max=50)])
    medical_authority = StringField('Medical Authority', validators=[Length(max=50)])
    membership_status = StringField('Membership Status', validators=[Length(max=20)])
    membership_number = StringField('Membership Number', validators=[Length(max=20)])
    experience = StringField('Experience')
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=2, max=100)])
    last_name = StringField('Last Name', validators=[Length(min=2, max=100)])
    email = StringField('Email', validators=[InputRequired(), Length(min=6, max=100)])
    phone_number = StringField('Phone Number')
    address = StringField('Address')
    submit = SubmitField('Save User')

class PatientForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(max=100)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(max=100)])
    date_of_birth = DateField('Date of Birth', validators=[InputRequired()])
    gender = SelectField('Gender', validators=[InputRequired()], choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')])
    national_id_number = StringField('Social Security Number', validators=[InputRequired(), Length(max=11)])
    address = StringField('Address', validators=[InputRequired(), Length(max=200)])
    phone_number = StringField('Phone Number', validators=[InputRequired(), Length(max=15)])
    email = StringField('Email', validators=[InputRequired(), Length(max=100)])
    emergency_contact_name = StringField('Emergency Contact Name', validators=[Length(max=100)])
    emergency_contact_number = StringField('Emergency Contact Number', validators=[Length(max=15)])
    insurance_provider = StringField('Insurance Provider', validators=[Length(max=100)])
    insurance_policy_number = StringField('Insurance Policy Number', validators=[Length(max=50)])
    primary_care_physician = StringField('Primary Care Physician', validators=[Length(max=100)])
    allergies = StringField('Allergies', validators=[Length(max=200)])
    medications = StringField('Medications', validators=[Length(max=200)])
    medical_conditions = StringField('Medical Conditions', validators=[Length(max=200)])
    surgeries = StringField('Surgeries', validators=[Length(max=200)])
    submit = SubmitField('Save Patient')

class PrescriptionForm(FlaskForm):
    patient_id = StringField('Patient ID', validators=[InputRequired()])
    medication = StringField('Medication', validators=[InputRequired(), Length(max=200)])
    dosage = StringField('Dosage', validators=[InputRequired(), Length(max=50)])
    instructions = StringField('Instructions', validators=[Length(max=200)])
    date_prescribed = DateField('Date Prescribed', validators=[InputRequired()])
    prescribing_physician = StringField('Prescribing Physician', validators=[InputRequired(), Length(max=100)])
    submit = SubmitField('Save Prescription')

class AppointmentForm(FlaskForm):
    user_id = StringField('User ID', validators=[InputRequired()])
    patient_id = StringField('Patient ID', validators=[InputRequired()])
    appointment_date = DateTimeField('Appointment Date', validators=[InputRequired()])
    appointment_type = StringField('Appointment Type', validators=[InputRequired(), Length(max=100)])
    notes = StringField('Notes', validators=[Length(max=200)])
    submit = SubmitField('Save Appointment')

class ContactUsForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    return render_template("index.html", form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            user = User.query.filter_by(username=username).first()
            
            if not user or not check_password_hash(user.password, password):
                flash('Please check your login details and try again.')
                return redirect(url_for('login'))

            login_user(user)
            return redirect(url_for('home'))

    return render_template("login.html", form=form)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
   
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            user = User.query.filter_by(username=username).first()
            if user:
                flash('Username already exists. Please choose a different one.')
                return redirect(url_for('login'))

            new_user = User(username=username, password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
          
            # Send email to the new user
            msg = Message(
                subject="Welcome to HippoHealth!",
                sender=app.config["MAIL_USERNAME"],
                recipients=[username],
                body=f"Hi {username},\n\nThank you for registering on our website. We are excited to have you as a member!\n\nBest regards,\nHippoHealth Team"
            )
            mail.send(msg)

            flash('Registration successful! An email has been sent to your email address.')
            user = User.query.filter_by(username=username).first()
            login_user(user)
            print("User Created")
            return redirect(url_for('home'))
    return render_template("register.html", form=form)

@login_required
@app.route("/home")
def home():
    form = ContactForm()
    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    trusted_contacts = Contact.query.filter_by(user_id=current_user.id, status="Trusted").all()
    untrusted_contacts = Contact.query.filter_by(user_id=current_user.id, status="Untrusted").all()
    return render_template("home.html", current_user=current_user, form=form, contacts=contacts, trusted_contacts=trusted_contacts, untrusted_contacts=untrusted_contacts)

@app.route("/what")
def what():
    return render_template("what.html")

@app.route("/how")
def how():
    return render_template("how.html")

@app.route("/getintouch", methods=["GET", "POST"])
def contact():
    form = ContactUsForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data

        msg = Message(
            subject="New Message from Contact Form",
            sender=app.config["MAIL_USERNAME"],
            recipients=["topolockapp@gmail.com"],
            body=f"Name: {name}\nEmail: {email}\nMessage: {message}"
        )

        mail.send(msg)

        flash("Your message has been sent successfully!", "success")
        return redirect(url_for("home"))

    return render_template("getintouch.html", form=form, current_user=current_user)

@app.route("/contacts")
@login_required
def contacts():
    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    return render_template("contacts.html", current_user=current_user, contacts=contacts)

import requests

@app.route("/create_contact", methods=["GET", "POST"])
@login_required
def create_contact():
    print("Config ID", log_config_id)
    print("API Token", api_token)
    if request.method == "POST":
        contact_type = request.form.get("contact_type")
        first_name = request.form.get("first_name")
        email = request.form.get("email")
        ip_address = request.form.get("ip_address")

        new_contact = Contact(
            contact_type=contact_type,
            first_name=first_name,
            email=email,
            ip_address=ip_address,
            user_id=current_user.id  
        )

        db.session.add(new_contact)
        db.session.commit()
        
        # Log the contact creation event
        log_data = {
            "config_id": f"{log_config_id}",
            'event': {
                'message': 'Creating Contact'
            }
        }
        headers = {
            'Authorization': f"Bearer {api_token}",
            'Content-Type': 'application/json'
        }
        
        response = requests.post('https://audit.aws.eu.pangea.cloud/v1/log', json=log_data, headers=headers)
        res = response.json()
        # Save the log data to the database
        log = Log(
            message=log_data['event']['message'],
            actor=current_user.id,
            action='create',
            target='Contact',
            status='success',
            request_time=res['request_time']
        )
        db.session.add(log)
        db.session.commit()

        return redirect(url_for("contacts"))
    
    return render_template("create_contact.html", current_user=current_user)

@app.route("/contacts/delete/<int:contact_id>", methods=["POST"])
@login_required
def delete_contact(contact_id):
    app.logger.info('Deleting contact with ID: %s', contact_id)

    contact = Contact.query.filter_by(user_id=current_user.id, id=contact_id).first()
    if contact:
        app.logger.info('Contact found. Deleting contact: %s', contact)
        db.session.delete(contact)
        db.session.commit()
    else:
        app.logger.warning('Contact not found with ID: %s', contact_id)

    # Log the contact deletion event
    log_data = {
        "config_id": f"{log_config_id}",
        'event': {
            'message': 'Deleting contact'
        }
    }
    headers = {
        'Authorization': f"Bearer {api_token}",
        'Content-Type': 'application/json'
    }

    response = requests.post('https://audit.aws.eu.pangea.cloud/v1/log', json=log_data, headers=headers)
    res = response.json()

    # Save the log data to the database
    log = Log(
        message=log_data['event']['message'],
        actor=current_user.id,
        action='delete',
        target='Contact',
        status='success',
        request_time=res['request_time']
    )
    db.session.add(log)
    db.session.commit()

    app.logger.info('Contact deletion completed')
    return redirect(url_for("contacts"))

@app.route("/contacts/edit/<int:contact_id>", methods=["GET", "POST"])
@login_required
def edit_contact(contact_id):
    contact = Contact.query.filter_by(user_id=current_user.id, id=contact_id).first()
    print("Contact: ", contact)
    if not contact:
        return redirect(url_for("contacts"))

    if request.method == "POST":
        # Update the contact object with the new data from the form
        print(request.form)
        contact.first_name = request.form.get("first_name")
        contact.last_name = request.form.get("last_name")
        contact.email = request.form.get("email")
        contact.phone_number = request.form.get("phone_number")
        contact.address = request.form.get("address")
        contact.status = request.form.get("status")
        contact.ip_address = request.form.get("ip_address")
        db.session.commit()

        # Log the contact update event
        log_data = {
            "config_id": f"{log_config_id}",
            'event': {
                'message': 'Updating Contact'
            }
        }
        headers = {
            'Authorization': f"Bearer {api_token}",
            'Content-Type': 'application/json'
        }

        response = requests.post('https://audit.aws.eu.pangea.cloud/v1/log', json=log_data, headers=headers)
        res = response.json()

        # Save the log data to the database
        log = Log(
            message=log_data['event']['message'],
            actor=current_user.id,
            action='update',
            target='Contact',
            status='success',
            request_time=res['request_time']
        )
        db.session.add(log)
        db.session.commit()

        print("Done, Saved Data!")
        return redirect(url_for("contacts"))
    else:
        return render_template("edit_contact.html", current_user=current_user, contact=contact)


@app.route("/verify/<int:contact_id>", methods=["POST"])
@login_required
def verify_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)

    # Perform verification process using the ip_address field
    verification_data = {
        "ip": contact.ip_address,
        "provider": "cymru"
    }
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    response = requests.post("https://ip-intel.aws.eu.pangea.cloud/v1/reputation", json=verification_data, headers=headers)

    # Handle the response as needed
    if response.status_code == 200:
        verification_result = response.json()
        verdict = verification_result.get("result", {}).get("data", {}).get("verdict")
        if verdict == "benign":
            contact.status = "Trusted"
        else:
            contact.status = "Untrusted"

        # Log the contact deletion event
        log_data = {
            "config_id": f"{log_config_id}",
            'event': {
                'message': 'Verifying contact'
            }
        }

        headers = {
            'Authorization': f"Bearer {api_token}",
            'Content-Type': 'application/json'
        }

        response = requests.post('https://audit.aws.eu.pangea.cloud/v1/log', json=log_data, headers=headers)
        res = response.json()

        # Save the log data to the database
        log = Log(
            message=log_data['event']['message'],
            actor=current_user.id,
            action='verify',
            target='Contact',
            status='success',
            request_time=res['request_time']
        )

        db.session.add(log)
  

        db.session.commit()

    return redirect(url_for("contacts"))

@app.route("/logs")
@login_required
def logs():
    user_id = current_user.id

    # Retrieve logs from the database with the current_user's id as the actor field
    logs = Log.query.filter_by(actor=user_id).all()
    for log in logs:
        print(log.request_time)

    return render_template("logs.html", logs=logs, moment=moment, datetime=datetime)

@app.route("/get_contact", methods=["GET", "POST"])
@login_required
def get_contact():
    if request.method == "POST":
        email = request.form.get("email")
        contact = Contact.query.filter_by(email=email).first()

        if contact:
            # Contact found, do something with it
            return render_template("contact_details.html", contact=contact)
        else:
            # Contact not found
            return render_template("contact_not_found.html")
    
    return render_template("get_contact.html", current_user=current_user)

@app.route("/trusted_contacts", methods=["GET"])
@login_required
def get_trusted_contacts():
    trusted_contacts = Contact.query.filter_by(status="Trusted").all()

    return render_template("trusted_contacts.html", contacts=trusted_contacts)

@app.route("/untrusted_contacts", methods=["GET"])
@login_required
def get_untrusted_contacts():
    untrusted_contacts = Contact.query.filter_by(status="Untrusted").all()

    return render_template("untrusted_contacts.html", contacts=untrusted_contacts)

@app.route("/latest_contact", methods=["GET"])
@login_required
def get_latest_contact():
    latest_contact = Contact.query.order_by(Contact.created_at.desc()).first()

    return render_template("latest_contact.html", contact=latest_contact)

@app.route("/docs")
def docs():
    return render_template("docs.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))