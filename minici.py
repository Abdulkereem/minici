from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
import string
import secrets
import os
import subprocess

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///projects.db'
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, username, password):
        self.username = username
        self.password = password


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    directory = db.Column(db.String(100))
    deploy_commands = db.Column(db.String(255))
    updated = db.Column(db.Boolean, default=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def generate_random_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password
@app.route('/migrate')
def migrate():
    # Create the database tables
    db.drop_all()
    db.create_all()
    
@app.route('/seed/<email>')
def seed(email:str):
    import os
    new_user = User(username=email,password=generate_random_password())
    db.session.add(new_user)
    db.session.commit()
    return new_user.password

@app.route('/')
@login_required
def dashboard():
    projects = Project.query.all()
    return render_template('dashboard.html', projects=projects)


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if request.method == 'POST':
        project_id = request.form.get('id')
        name = request.form['name']
        directory = request.form['directory']
        deploy_commands = request.form['deploy_commands']

        if project_id:
            # Update existing project
            project = Project.query.get(project_id)
            if project:
                project.name = name
                project.directory = directory
                project.deploy_commands = deploy_commands
        else:
            # Create a new project
            project = Project(name=name, directory=directory, deploy_commands=deploy_commands)
            db.session.add(project)

        db.session.commit()

        return redirect('/')

    # Handle GET request for rendering the registration/editing form
    project_id = request.args.get('id')
    project = None
    if project_id:
        project = Project.query.get(project_id)

    return render_template('register.html', project=project)


@app.route('/deploy/<int:project_id>', methods=['GET', 'POST'])
@login_required
def deploy(project_id):
    project = Project.query.get(project_id)
    if project:
        if request.method == 'POST':
            if request.form.get('confirm') == 'yes':
                os.chdir(project.directory)
                subprocess.run(['git', 'pull'])
                subprocess.run(project.deploy_commands.split(','), shell=True)

                project.updated = False
                db.session.commit()

    return render_template('deploy.html', project=project)


@app.route('/rebuild/<int:project_id>', methods=['POST'])
@login_required
def rebuild(project_id):
    project = Project.query.get(project_id)
    if project:
        os.chdir(project.directory)
        subprocess.run(project.deploy_commands.split(','), shell=True)

        project.updated = False
        db.session.commit()

    return redirect('/')


@app.route('/run-command/<int:project_id>', methods=['POST'])
@login_required
def run_command(project_id):
    project = Project.query.get(project_id)
    if project:
        command = request.form['command']
        os.chdir(project.directory)
        subprocess.run(command.split(','), shell=True)

    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            login_user(user)
            return redirect('/')

    return render_template('signin.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
