from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user 
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from datetime import datetime
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'secretkeylmao'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

class Todo(db.Model):
    id  = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255), nullable=False)
    completed = db.Column(db.Integer, default=0)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Task %r>' % self.id
    
with app.app_context():
        db.create_all()

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_usename = User.query.filter_by(username=username.data).first()
        if existing_usename:
            raise ValidationError("That username already exists")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

@app.route('/', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('taskMaster'))
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register/', methods=['GET','POST'])
def register():

    form = RegisterForm()

    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hash_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))
    
    return render_template('register.html', form=form)

@app.route('/dashboard/', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/task_master/', methods=['POST', 'GET'])
@login_required
def taskMaster():
    if request.method == 'POST':
        task_content = request.form['content']
        new_task = Todo(content=task_content)
        
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/task_master/')
        except:
            return 'There was an issue adding your task. Please try again'
    else:
        tasks = Todo.query.order_by(Todo.date_created).all()
        return render_template('login.html', tasks=tasks)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/task_master/')
    except:
        return 'There was an issue with deleting your task'

@app.route('/update/<int:id>', methods=['GET','POST'])
@login_required
def update(id):

    task = Todo.query.get_or_404(id)
    if request.method == 'POST':
        task.content = request.form['content']
        
        try:
            db.session.commit()
            return redirect('/task_master/')
        except:
            return 'There was an issue with updating your task'

    else:
        return render_template('update.html', task=task)

if __name__ == "__main__":
    app.run(debug=True)
