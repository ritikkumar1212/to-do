from flask import Flask, render_template, redirect, url_for, request, jsonify, make_response,flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'a6c1f3221b07477870847438cc9a0b7a'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(db.Model, UserMixin):
    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(25), nullable=False)
    routines = db.relationship('Routine', backref='user', lazy=True)
    def get_id(self):
        return str(self.user_id)

class Routine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub = db.Column(db.String(10), nullable=False)
    hr = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        
        if not token:
            return jsonify({'message': 'a valid token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(user_name=data['user_name']).first()
        except:
            return jsonify({'message': 'token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorator

class SignupForm(FlaskForm):
    user_name = StringField(validators=[InputRequired(),Length(
       min=4, max=20)],render_kw={"placeholder":"Username"})
 
    password = PasswordField(validators=[InputRequired(),Length(
       min=4, max=20)],render_kw={"placeholder":"password"})
    submit = SubmitField("Signup")
 
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
           username=username.data).first()
        if existing_user_username:
            raise ValidationError(
               'This  username already exists in the database. Please Choose Different Username.')
 
class LoginForm(FlaskForm):
    user_name = StringField(validators=[
                          InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
 
    password = PasswordField(validators=[
                            InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
 
    submit = SubmitField('Login')

class CreateRoutineForm(FlaskForm):
    sub = StringField('Subject Name', validators=[InputRequired(), Length(min=1, max=100)])
    hr = IntegerField('Hours', validators=[InputRequired()])
    submit = SubmitField('Create Routine')


@app.route('/register', methods=['POST','GET'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
       hashed_password = generate_password_hash(form.password.data)
       new_user = User(user_name=form.user_name.data, password=hashed_password)
       db.session.add(new_user)
       db.session.commit()
       return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.user_name.data  
        password = form.password.data
        user = User.query.filter_by(user_name=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            token = jwt.encode({'user_name': user.user_name, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}, app.config['SECRET_KEY'])
            flash('Login successful!', 'success')
            return redirect(url_for('profile')) 
        else:
            flash('Invalid email or password', 'danger')
            
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET'])
def get_users():
    Users = User.query.all()

    return jsonify([{"id": emp.user_id, "name": emp.user_name, "password": emp.password} for emp in Users])



@app.route('/')
def home():
   return render_template('home.html')

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    return render_template('profile.html',user=current_user)


@app.route('/routine/<int:sub_id>', methods=['GET'])
@login_required
def get_list_by_id(sub_id):
    subj = Routine.query.get(sub_id)
    if subj:
        return jsonify({'id': subj.id, 'sub': subj.sub, 'hr': subj.hr})
    return jsonify({"error": "id not found"})

@app.route('/routine', methods=['GET', 'POST'])
@login_required
def creating_task():
    form = CreateRoutineForm()
    
    if form.validate_on_submit():
        new_routine = Routine(
            sub=form.sub.data,
            hr=form.hr.data,
            user_id=current_user.user_id  
        )      
        db.session.add(new_routine)
        db.session.commit()
        return redirect(url_for('profile'))  
        

    return render_template('create_routine.html', form=form)

@app.route('/routine/<int:sub_id>', methods=['DELETE'])
@login_required
def delete_task(sub_id):
    subj = Routine.query.get(sub_id)
    if not subj:
        return jsonify({'error': "ID NOT FOUND"})
    db.session.delete(subj)
    db.session.commit()
    return jsonify("record deleted successfully")

@app.route('/routine/<int:sub_id>', methods=['PUT'])
@login_required
def update_task(sub_id):
    subj = Routine.query.get(sub_id)
    if not subj:
        return jsonify({'error': 'Invalid id'})
    data = request.json
    subj.sub = data['sub']
    subj.hr = data['hr']
    db.session.commit()
    return jsonify({'id': subj.id, 'sub': subj.sub, 'hr': subj.hr})

if __name__ == '__main__':
    app.run(debug=True)
