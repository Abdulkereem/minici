from flask import Flask, render_template, request, redirect, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
import string
import secrets
import os
import subprocess
from werkzeug.security import generate_password_hash, check_password_hash

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
        self.password = generate_password_hash(password)  # Hash the password


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    directory = db.Column(db.String(100))
    deploy_commands = db.Column(db.String(255))
    updated = db.Column(db.Boolean, default=False)
    is_deployed = db.Column(db.Boolean, default=False)
    github_token = db.Column(db.String(255))  # Column for storing GitHub token


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
        github_token = request.form.get('github_token')

        if project_id:
            # Update existing project
            project = Project.query.get(project_id)
            if project:
                project.name = name
                project.directory = directory
                project.deploy_commands = deploy_commands
                project.github_token = github_token
        else:
            # Create a new project
            project = Project(name=name, directory=directory, deploy_commands=deploy_commands, github_token=github_token)
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

                # Get the existing remote URL
                original_remote_url = subprocess.check_output(['git', 'remote', 'get-url', 'origin']).strip().decode('utf-8')

                # Modify the remote URL to include the GitHub token
                if project.github_token:
                    modified_remote_url = original_remote_url.replace('https://', f'https://{project.github_token}@')

                    # Set the modified remote URL
                    subprocess.run(['git', 'remote', 'set-url', 'origin', modified_remote_url], shell=True)

                # Perform the git pull command
                subprocess.run(['git', 'pull'], shell=True)

                # Reset the remote URL back to the original if it was changed
                if project.github_token:
                    subprocess.run(['git', 'remote', 'set-url', 'origin', original_remote_url], shell=True)

                subprocess.run(project.deploy_commands.split(','), shell=True)

                project.updated = False
                db.session.commit()

    return render_template('deploy.html', project=project)


@app.route('/rebuild/<int:project_id>', methods=['GET'])
@login_required
def rebuild(project_id):
    project = Project.query.get(project_id)
    if project:
        os.chdir(project.directory)
        
        # Capture the output of the command
        result = subprocess.run(project.deploy_commands.split(','), shell=True, capture_output=True, text=True)
        
        project.updated = False
        db.session.commit()

        # Return the output as part of the response
        return render_template('terminal_output.html', output=result.stdout, error=result.stderr,project=project)

    return redirect('/')


@app.route('/terminal', methods=['POST', 'GET'])
@login_required
def terminal():
    if request.method == 'POST':
        print(request.json)
        command = request.json['command']
        
        # Capture the output of the command
        result = subprocess.run(command.split(','), shell=True, capture_output=True, text=True)

        # Return the output as a JSON response
        return jsonify({
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        })
    else:  # Handle GET request
        return render_template('terminal.html', output='', error='', returncode=0)






@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/')

    return render_template('signin.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user:
            flash('Username already exists. Please choose a different one.', 'danger')  # Flash message for existing user
        else:
            new_user = User(username=username, password=password)  # Create new user
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! You can now log in.', 'success')  # Flash message for successful signup
            return redirect('/login')  # Redirect to login after successful signup

    return render_template('signup.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/delete/<int:project_id>', methods=['GET'])
@login_required
def delete_project(project_id):
    project = Project.query.get(project_id)
    if project:
        db.session.delete(project)
        db.session.commit()
    return redirect('/')


@app.route('/edit/<int:project_id>', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get(project_id)
    if not project:
        flash('Project not found.', 'danger')
        return redirect('/')

    if request.method == 'POST':
        project.name = request.form['name']
        project.directory = request.form['directory']
        project.deploy_commands = request.form['deploy_commands']
        project.github_token = request.form.get('github_token')
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect('/')

    return render_template('edit_project.html', project=project)


if __name__ == '__main__':
    app.run(debug=True,port=5001)
