from flask import Flask, render_template, request, redirect , current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
import string
import secrets
import os
import subprocess
import threading

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///projects.db'
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Watch Thread
watch_thread = None
watch_thread_stop_event = threading.Event()


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


class WatchList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    project = db.relationship('Project', backref='watchlist')

    def __init__(self, project):
        self.project = project


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def generate_random_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


def deployment_thread():
    while not watch_thread_stop_event.is_set():
        # Retrieve projects on the watch list
        with current_app.app_context():
            watch_list = WatchList.query.all()

            for watch_item in watch_list:
                project = watch_item.project

                os.chdir(project.directory)
                subprocess.run(['git', 'pull'])
                subprocess.run(project.deploy_commands.split(','), shell=True)

                project.updated = False
                db.session.commit()

        watch_thread_stop_event.wait(60)  # Check every 60 seconds


@app.route('/migrate')
def migrate():
    # Create the database tables
    db.drop_all()
    db.create_all()


@app.route('/seed/<email>')
def seed(email: str):
    import os
    new_user = User(username=email, password=generate_random_password())
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


@app.route('/watch-push', methods=['POST'])
def watch_push():
    payload = request.json
    if payload:
        project_id = payload.get('project_id')
        project = Project.query.get(project_id)
        if project:
            watch_item = WatchList(project=project)
            db.session.add(watch_item)
            db.session.commit()

    return 'OK'


if __name__ == '__main__':
    # Start the deployment thread
    watch_thread = threading.Thread(target=deployment_thread)
    watch_thread.start()

    app.run(debug=True)

