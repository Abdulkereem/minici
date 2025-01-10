from flask import Flask, render_template, request, redirect, flash, jsonify, send_from_directory, url_for , send_file , session , Response , stream_with_context
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user , current_user
import string
import secrets
import os
import subprocess
from werkzeug.security import generate_password_hash, check_password_hash
import mimetypes
import platform
import psutil
import socket
import uuid  # Import the uuid module
import shutil
import time
import queue
from datetime import datetime
import threading
import json
from gateway import *



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///projects.db'
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
db = SQLAlchemy(app)

DEFAULT_DIRECTORY = os.path.abspath("/")


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


deployment_logs = {}

class DeploymentLogger:
    def __init__(self, project_id):
        self.project_id = project_id
        self.logs = queue.Queue()
        self.complete = False
    
    def add_log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "message": message,
            "level": level
        }
        self.logs.put(log_entry)
    
    def mark_complete(self):
        self.complete = True


def generate_random_folder_name(length=8):
    """Generate a random folder name."""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)  # Hash the password


class Project(db.Model):
    id                  = db.Column(db.Integer, primary_key=True)
    name                = db.Column(db.String(100))
    directory           = db.Column(db.String(100))
    deploy_commands     = db.Column(db.String(255))
    updated             = db.Column(db.Boolean, default=False)
    is_deployed         = db.Column(db.Boolean, default=False)
    github_token        = db.Column(db.String(255))  # Column for storing GitHub token
    git_repo            = db.Column(db.String(255))  # Column for storing GitHub token
    deploy_triger      = db.Column(db.String(255))  # Column for storing GitHub token
    branch              = db.Column(db.String(255))  # Column for storing GitHub token
    domain_name         = db.Column(db.String(255))
    port                = db.Column(db.String(255))
    hook_id            = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True)  # Auto-generated UUID




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def generate_random_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


def get_files_with_name_and_path(directory):
    """
    Get a list of dictionaries representing files in the given directory.
    Each dictionary contains the file name and its absolute path.

    Args:
        directory (str): The directory to list files from.

    Returns:
        list: A list of dictionaries with keys 'name' and 'path'.
    """
    try:
        # Normalize the directory path
        directory = os.path.abspath(directory)

        # Ensure the directory exists
        if not os.path.isdir(directory):
            raise ValueError(f"Provided path '{directory}' is not a valid directory.")

        # Get all files in the directory
        files = [
            {"name": item, "path": os.path.join(directory, item)}
            for item in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, item))
        ]
        return files
    except Exception as e:
        print(f"Error retrieving files: {e}")
        return []

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
    # System stats
    system_stats = {
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
    }
    
    # Count statistics
    stats = {
        'project_count': Project.query.count(),
        'file_count': 0,
        'user_count': User.query.count(),
        'gateway_status': 'Active' if os.system('systemctl is-active nginx') == 0 else 'Inactive'
    }
    
    return render_template('dashboard.html', 
                         current_page='dashboard',
                         **system_stats,
                         **stats)

@app.route('/api/system-stats')
@login_required
def system_stats():
    return jsonify({
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent
    })








@app.route('/projects')
@login_required
def project():
    projects = Project.query.all()
    return render_template('projects.html', projects=projects)


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if request.method == 'POST':
        directory = generate_random_folder_name()  # Generate a random folder name for the directory
        name                = request.form['name']
        deploy_commands     = request.form['deploy_commands']
        github_token        = request.form['github_token']
        branch              = request.form['branch']
        port                = request.form['port']
        domain_name         = request.form['domain_name']
        deploy_triger       = request.form['deploy_triger']
        git_repo            = request.form['git_repo']

        project = Project(name=name, directory=directory,
                            deploy_commands=deploy_commands,
                            github_token=github_token,
                            port=port,
                            git_repo=git_repo,
                            branch=branch,
                            domain_name=domain_name,
                            deploy_triger=deploy_triger)
        db.session.add(project)

        db.session.commit()

        return redirect(url_for('project'))

    # Handle GET request for rendering the registration/editing form

    return render_template('register.html')





# @app.route('/deploy/<int:project_id>', methods=['GET', 'POST'])
# @login_required
# def deploy(project_id):
#     project = Project.query.get(project_id)
#     if project:
#         if request.method == 'POST':
#             # Define the base directory for projects
#             base_directory = os.path.join(os.getcwd(), 'projects')
#             project.directory = os.path.join(base_directory, project.directory)  # Set the full path for the project directory

#             # Check if the project directory exists, if not, create it
#             if not os.path.exists(project.directory):
#                 os.makedirs(project.directory)  # Create the directory if it doesn't exist

#             os.chdir(project.directory)

#             # Remove all folders inside the project directory
#             for item in os.listdir(project.directory):
#                 item_path = os.path.join(project.directory, item)
#                 if os.path.isdir(item_path):
#                     shutil.rmtree(item_path)  # Delete the folder

#             # Construct the clone URL correctly
#             clone_url = f"https://{project.github_token}@github.com/{project.git_repo}"
#             print()

#             # Debug print statement to check the clone URL
#             print(f"Cloning repository from: {clone_url}")

#             result = subprocess.run(['git', 'clone', clone_url, '.'], cwd=project.directory, capture_output=True, text=True)

#             # Check if the clone was successful
#             if result.returncode != 0:
#                 flash(f"Error cloning repository: {result.stderr}", 'danger')
#                 return redirect(url_for('project'))  # Redirect to the project page or handle as needed

#             # Check for the existence of the Dockerfile
#             dockerfile_path = os.path.join(project.directory, 'Dockerfile')
#             if not os.path.isfile(dockerfile_path):
#                 flash(f"Dockerfile not found in the project directory: {project.directory}", 'warning')
#                 return redirect(url_for('project'))  # Redirect to the project page or handle as needed

#             # Run the deploy commands
#             subprocess.run(project.deploy_commands.split(','), shell=True, cwd=project.directory)

#             project.updated = False
#             db.session.commit()

#     return render_template('deploy.html', project=project)



@app.route('/deploy/<int:project_id>', methods=['GET', 'POST'])
@login_required
def deploy(project_id):
    project = Project.query.get(project_id)
    if project and request.method == 'POST':
        print("Go!!!")
        # Create a new logger for this deployment
        logger = DeploymentLogger(project_id)
        deployment_logs[project_id] = logger

        def deployment_task():
            # Base directory setup
            base_directory = os.path.join(os.getcwd(), 'projects')
            project.directory = os.path.join(base_directory, project.directory)

            # Check if the project directory exists
            if os.path.exists(project.directory):
                # Remove the existing directory and its contents
                shutil.rmtree(project.directory)  # Remove the directory and its contents

            # Create the project directory
            os.makedirs(project.directory, exist_ok=True)  # Create the project directory

            # Use the project name for the log file
            log_file_path = os.path.join(project.directory, f'{project.name}_deployment.log')
            
            # Ensure the directory for the log file exists
            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)  # Create the directory if it doesn't exist
            
            with open(log_file_path, 'a') as log_file:  # Open log file in append mode
                with app.app_context():  # Add application context here
                    try:
                        # Log the start of deployment
                        logger.add_log(f"Starting deployment for {project.name}")
                        log_file.write(f"{datetime.now()}: Starting deployment for {project.name}\n")
                        print('starting...')

                        # Base directory setup
                        base_directory = os.path.join(os.getcwd(), 'projects')
                        project.directory = os.path.join(base_directory, project.directory)
                        logger.add_log(f"Project directory: {project.directory}")
                        log_file.write(f"{datetime.now()}: Project directory: {project.directory}\n")

                        # Cleanup: Remove all contents inside the project directory if it exists
                        if os.path.exists(project.directory):
                            logger.add_log("Cleaning existing contents in the project directory...")
                            log_file.write(f"{datetime.now()}: Cleaning existing contents in the project directory...\n")
                            for item in os.listdir(project.directory):
                                item_path = os.path.join(project.directory, item)
                                if os.path.isdir(item_path):
                                    shutil.rmtree(item_path)  # Delete the folder
                                    logger.add_log(f"Removed directory: {item}")
                                    log_file.write(f"{datetime.now()}: Removed directory: {item}\n")
                                else:
                                    os.remove(item_path)  # Delete the file
                                    logger.add_log(f"Removed file: {item}")
                                    log_file.write(f"{datetime.now()}: Removed file: {item}\n")

                        # Ensure the project directory exists
                        os.makedirs(project.directory, exist_ok=True)
                        logger.add_log("Ensured project directory exists")
                        log_file.write(f"{datetime.now()}: Ensured project directory exists\n")

                        os.chdir(project.directory)
                        # Clone repository
                        clone_url = f"https://{project.github_token}@github.com/{project.git_repo}"
                        logger.add_log("Cloning repository...")
                        log_file.write(f"{datetime.now()}: Cloning repository...\n")
                        result = subprocess.run(
                            ['git', 'clone', '-b', project.branch, clone_url, '.'],
                            cwd=project.directory,
                            capture_output=True,
                            text=True
                        )

                        if result.returncode != 0:
                            logger.add_log(f"Error cloning repository: {result.stderr}", "ERROR")
                            log_file.write(f"{datetime.now()}: Error cloning repository: {result.stderr}\n")
                            raise Exception("Clone failed")

                        logger.add_log("Repository cloned successfully")
                        log_file.write(f"{datetime.now()}: Repository cloned successfully\n")

                        # Check for Dockerfile
                        dockerfile_path = os.path.join(project.directory, 'Dockerfile')
                        if not os.path.isfile(dockerfile_path):
                            logger.add_log("Dockerfile not found", "ERROR")
                            log_file.write(f"{datetime.now()}: Dockerfile not found\n")

                        # Run deployment commands
                        for command in project.deploy_commands.split(','):
                            logger.add_log(f"Executing: {command}")
                            log_file.write(f"{datetime.now()}: Executing: {command}\n")
                            result = subprocess.run(
                                command.strip(),
                                shell=True,
                                cwd=project.directory,
                                capture_output=True,
                                text=True
                            )
                            if result.stdout:
                                logger.add_log(result.stdout)
                                log_file.write(f"{datetime.now()}: {result.stdout}\n")
                            if result.stderr:
                                logger.add_log(result.stderr, "WARNING")
                                log_file.write(f"{datetime.now()}: {result.stderr}\n")

                        project.updated = False
                        project.is_deployed = True
                        db.session.commit()
                        
                        logger.add_log("Deployment completed successfully")
                        log_file.write(f"{datetime.now()}: Deployment completed successfully\n")
                        
                    except Exception as e:
                        logger.add_log(f"Deployment failed: {str(e)}", "ERROR")
                        log_file.write(f"{datetime.now()}: Deployment failed: {str(e)}\n")
                    finally:
                        logger.mark_complete()

        # Start deployment in a background thread
        thread = threading.Thread(target=deployment_task)
        thread.start()
        
        return redirect(url_for('project_log', project_id=project_id))

    return render_template('deploy.html', project=project)




@app.route('/project_log/<int:project_id>')
def project_log(project_id):
    project = Project.query.get(project_id)
    return render_template('project_log.html',
                           project_id=project_id,project=project)



@app.route('/logs/<int:project_id>/stream')
@login_required
def stream_logs(project_id):
    def generate():
        logger = deployment_logs.get(project_id)
        if not logger:
            return
            
        while not logger.complete or not logger.logs.empty():
            try:
                log_entry = logger.logs.get(timeout=1)
                yield f"data: {json.dumps(log_entry)}\n\n"
            except queue.Empty:
                if logger.complete:
                    break
                continue

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream'
    )



@app.route('/api/logs/<int:project_id>')
@login_required
def get_logs(project_id):
    logger = deployment_logs.get(project_id)
    if not logger:
        return jsonify({'logs': []})
    
    logs = []
    while not logger.logs.empty():
        logs.append(logger.logs.get())
    return jsonify({'logs': logs})


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


@app.route('/run-command/<int:project_id>', methods=['POST', 'GET'])
@login_required
def run_command(project_id):
    project = Project.query.get(project_id)
    if project:
        if request.method == 'POST':
            print(request.json)
            command = request.json['command']
            os.chdir(project.directory)
            # Capture the output of the command
            result = subprocess.run(command.split(','), shell=True, capture_output=True, text=True)

            # Return the output as a JSON response
            return jsonify({
                'output': result.stdout,
                'error': result.stderr,
                'returncode': result.returncode
            })
        else:  # Handle GET request
            return render_template('terminal_output.html', output='', error='', returncode=0, project=project)

    return jsonify({'error': 'Project not found.'}), 404


@app.route("/terminal", methods=["GET", "POST"])
def terminal():
    if "current_dir" not in session:
        session["current_dir"] = DEFAULT_DIRECTORY

    current_dir = session.get("current_dir", DEFAULT_DIRECTORY)

    if request.method == "POST":
        command = request.json.get("command", "")
        if not command:
            return jsonify({"error": "No command provided", "returncode": 1})

        try:
            if command.startswith("cd "):  # Handle 'cd' commands
                path = command[3:].strip()
                new_dir = os.path.abspath(os.path.join(current_dir, path))
                if os.path.isdir(new_dir):
                    session["current_dir"] = new_dir
                    return jsonify({"output": f"Changed directory to {new_dir}", "returncode": 0})
                else:
                    return jsonify({"error": f"No such directory: {path}", "returncode": 1})
            else:  # Handle other commands
                result = subprocess.run(
                    command,
                    shell=True,
                    cwd=current_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                print(result)
                return jsonify({
                    "output": result.stdout,
                    "error": result.stderr,
                    "returncode": result.returncode
                })
        except Exception as e:
            return jsonify({"error": str(e), "returncode": 1})

    # Render the template on GET request with the current directory
    return render_template(
        "terminal.html",
        current_dir=current_dir,
        output="",
        error="",
        returncode=0,
    )







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
        # Delete the project directory
        if os.path.exists(project.directory):
            shutil.rmtree(project.directory)  # Remove the directory and its contents
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
        project.branch = request.form.get('branch')
        project.domain_name = request.form.get('domain_name')
        project.port = request.form.get('port')
        project.git_repo = request.form.get('git_repo')
        project.deploy_triger = request.form.get('deploy_triger')
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect('/')

    return render_template('edit_project.html', project=project)



def get_full_path(relative_path):
    """
    Combines the system root with a relative path.

    :param relative_path: The relative path to append to the system root (e.g., 'home').
    :return: The combined full path.
    """
    system_root = os.path.abspath(os.sep)  # Get the system root
    return os.path.join(system_root, relative_path)

def get_items_with_name_and_path(full_path):
    """
    Returns a list of dictionaries where each dictionary represents an item 
    in the directory with 'name' and 'path' as keys.

    :param full_path: The directory path to list items from.
    :return: List of dictionaries [{"name": item_name, "path": absolute_path}, ...]
    """
    if not os.path.isdir(full_path):
        raise ValueError(f"{full_path} is not a valid directory.")

    items = os.listdir(full_path)
    return [{"name": item, "path": os.path.abspath(os.path.join(full_path, item))} for item in items]




@app.route('/file_viewer', methods=['GET'])
@login_required
def file_viewer():
    file_path = request.args.get('file', None)

    if not file_path or not os.path.isfile(file_path):
        print('from here ')
        flash(f'Invalid or missing file path: {file_path}', 'danger')
        return redirect(url_for('file_management'))

    # Detect the file type
    mime_type, _ = mimetypes.guess_type(file_path)

    try:
        if mime_type:
            if mime_type.startswith('image/') or mime_type == 'application/pdf':
                # Make images and PDFs downloadable
                return send_file(file_path, as_attachment=True)
            elif mime_type.startswith('text/') or file_path.endswith(('.php', '.py', '.json', '.html')):
                # Render text-based files (e.g., .txt, .json, .html, .php, .py)
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                return render_template('text_editor.html', file_path=file_path, content=content)
            else:
                # For other file types, provide a download link
                return send_file(file_path, as_attachment=True)
        else:
            # Default: Download unsupported files
            flash('File type not recognized, defaulting to download.', 'info')
            return send_file(file_path, as_attachment=True)
    except Exception as e:
        print(e)
        flash(f'Error handling file: {e}', 'danger')
        return redirect(url_for('file_management'))



@app.route('/save-file', methods=['POST'])
@login_required
def save_file():
    try:
        data = request.get_json()
        file_path = data.get('file_path')
        content = data.get('content')

        if not file_path or not content:
            return jsonify({'success': False, 'message': 'Missing file path or content'}), 400

        # Validate file path is within allowed directory
        full_path = os.path.abspath(file_path)
        if not full_path.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
            return jsonify({'success': False, 'message': 'Invalid file path'}), 403

        # Save the file
        with open(full_path, 'w', encoding='utf-8') as file:
            file.write(content)

        return jsonify({'success': True, 'message': 'File saved successfully'})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/files', methods=['GET', 'POST'])
@login_required
def file_management():
    current_dir = request.args.get('dir', os.path.abspath(os.sep))
    full_path = get_full_path(current_dir)  # Converts to an absolute path

    # Check if the provided path is a file
    if os.path.isfile(full_path):
        print('here 1')
        return redirect(url_for('file_viewer', file=full_path))
    # Validate the directory
    if not os.path.exists(full_path) or not os.path.isdir(full_path):
        print('here 2')
        flash(f'The specified directory "{current_dir}" does not exist or is not valid.', 'danger')
        return redirect(url_for('file_management', dir=''))

    if request.method == 'POST':
        # Handle file upload
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        try:
            file.save(os.path.join(full_path, file.filename))
            flash('File uploaded successfully!', 'success')
        except Exception as e:
            flash(f'Error saving file: {e}', 'danger')
        return redirect(url_for('file_management', dir=current_dir))

    try:
        # List files and directories
        files = get_files_with_name_and_path(full_path)
        directories = get_items_with_name_and_path(full_path)
    except Exception as e:
        flash(f'Error accessing directory: {e}', 'danger')
        return redirect(url_for('file_management', dir=''))

    return render_template(
        'file_management.html',
        files=files,
        current_dir=current_dir,
        directories=directories
    )




@app.route('/files/<path:filename>', methods=['GET'])
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/delete-file/<path:filename>', methods=['POST'])
@login_required
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('File deleted successfully!', 'success')
    else:
        flash('File not found.', 'danger')
    return redirect(request.referrer)

@app.route('/create-directory', methods=['POST'])
@login_required
def create_directory():
    new_dir = request.form['directory_name']
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], new_dir)
    os.makedirs(full_path, exist_ok=True)
    flash('Directory created successfully!', 'success')
    return redirect(url_for('file_management'))



@app.route('/settings', methods=['GET'])
@login_required
def settings():
    # System Information
    system_info = {
        'os_info': f"{platform.system()} {platform.release()}",
        'ip_address': socket.gethostbyname(socket.gethostname()),
        'python_version': platform.python_version(),
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent
    }
    
    # Get list of users (if admin)
    users = User.query.all()
    
    return render_template('settings.html', 
                         current_page='settings',
                         users=users,
                         **system_info)


@app.route('/api/system-info')
@login_required
def system_info():
    return jsonify({
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent
    })

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        
        current_user.username = username
        current_user.email = email
        db.session.commit()
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('settings'))
    

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('settings'))
            
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('settings'))
            
        current_user.set_password(new_password)
        db.session.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('settings'))



@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        flash('Permission denied', 'danger')
        return redirect(url_for('settings'))
    username = request.form.get('new_username')
    email = request.form.get('new_email')
    password = request.form.get('new_user_password')
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('settings'))
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash('User created successfully!', 'success')
    return redirect(url_for('settings'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Permission denied', 'danger')
        return redirect(url_for('settings'))
        
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot delete your own account', 'danger')
        return redirect(url_for('settings'))

    db.session.delete(user)
    db.session.commit()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('settings'))


@app.route('/webhook/<string:hook_id>', methods=['POST'])
def github_webhook(hook_id):
    project = Project.query.filter_by(hook_id=hook_id).first()
    if not project:
        return jsonify({'error': 'Project not found'}), 404

    data = request.json
    print(data)
    if data is None:
        return jsonify({'error': 'Invalid JSON payload'}), 400

    # Check for action and conclusion in the payload
    action = data.get('action')
    conclusion = data.get('workflow_run', {}).get('conclusion')
    event_type = data.get('event', '')  # Get the event type from the payload

    # Check if the event type matches the project's deploy trigger
    if project.deploy_triger == event_type and action == "completed" and conclusion == "success":
        branch = data.get('workflow_run', {}).get('head_branch')
        if not branch:
            return jsonify({'error': 'Branch not specified'}), 400

        if branch == project.branch:
            logger = DeploymentLogger(project.id)
            deployment_logs[project.id] = logger

            def deployment_task():
                with app.app_context():
                    try:
                        logger.add_log(f"Starting deployment for {project.name}")
                        base_directory = os.path.join(os.getcwd(), 'projects')
                        project.directory = os.path.join(base_directory, project.directory)
                        logger.add_log(f"Project directory: {project.directory}")

                        try:
                            if os.path.exists(project.directory):
                                logger.add_log("Cleaning existing contents in the project directory...")
                                for item in os.listdir(project.directory):
                                    item_path = os.path.join(project.directory, item)
                                    if os.path.isdir(item_path):
                                        shutil.rmtree(item_path)
                                        logger.add_log(f"Removed directory: {item}")
                                    else:
                                        os.remove(item_path)
                                        logger.add_log(f"Removed file: {item}")
                        except Exception as e:
                            logger.add_log(f"Error cleaning project directory: {str(e)}", "ERROR")

                        os.makedirs(project.directory, exist_ok=True)
                        logger.add_log("Ensured project directory exists")

                        clone_url = f"https://{project.github_token}@github.com/{project.git_repo}"
                        logger.add_log("Cloning repository...")
                        result = subprocess.run(
                            ['git', 'clone', '-b', project.branch, clone_url, '.'],
                            cwd=project.directory,
                            capture_output=True,
                            text=True
                        )

                        if result.returncode != 0:
                            logger.add_log(f"Error cloning repository: {result.stderr}", "ERROR")
                            raise Exception("Clone failed")

                        logger.add_log("Repository cloned successfully")

                        dockerfile_path = os.path.join(project.directory, 'Dockerfile')
                        if not os.path.isfile(dockerfile_path):
                            logger.add_log("Dockerfile not found", "WARNING")

                        for command in project.deploy_commands.split(','):
                            logger.add_log(f"Executing: {command}")
                            result = subprocess.run(
                                command.strip(),
                                shell=True,
                                cwd=project.directory,
                                capture_output=True,
                                text=True
                            )
                            if result.stdout:
                                logger.add_log(result.stdout)
                            if result.stderr:
                                logger.add_log(result.stderr, "WARNING")

                        project.updated = False
                        project.is_deployed = True
                        db.session.commit()
                        logger.add_log("Deployment completed successfully")
                    except Exception as e:
                        logger.add_log(f"Deployment failed: {str(e)}", "ERROR")
                    finally:
                        logger.mark_complete()

            thread = threading.Thread(target=deployment_task)
            thread.start()
            return jsonify({'message': 'Deployment started'}), 202

    return jsonify({'message': 'No action taken'}), 200





@app.route('/domains')
def domains():
    projects = Project.query.all()
    active_domains = [p for p in projects if p.domain_name and p.is_deployed]
    pending_domains = [p for p in projects if p.domain_name and not p.is_deployed]
    
    return render_template('domains.html', 
                         domains=active_domains + pending_domains,
                         projects=projects,
                         current_page='domains')

@app.route('/domains/add', methods=['POST'])
def add_domain():
    domain = request.form.get('domain')
    project_id = request.form.get('project')
    
    if not domain:
        return jsonify({'success': False, 'error': 'Domain name is required'})
    
    try:
        project = Project.query.get(project_id)
        if not project:
            return jsonify({'success': False, 'error': 'Project not found'})
        
        # Update project with domain
        project.domain_name = domain
        db.session.commit()
        
        # Generate and save Nginx config
        config = generate_nginx_config(domain, project.port)
        config_path = f'/etc/nginx/sites-available/{domain}'
        
        # Write configuration file
        with open(config_path, 'w') as f:
            f.write(config)
        
        # Create symlink in sites-enabled
        symlink_path = f'/etc/nginx/sites-enabled/{domain}'
        if not os.path.exists(symlink_path):
            os.symlink(config_path, symlink_path)
        
        # Reload Nginx
        success, message = reload_nginx()
        if not success:
            # Cleanup on failure
            os.remove(config_path)
            if os.path.exists(symlink_path):
                os.remove(symlink_path)
            return jsonify({'success': False, 'error': f'Failed to reload Nginx: {message}'})
        
        flash('Domain added successfully', 'success')
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/domains/delete/<int:project_id>')
def delete_domain(project_id):
    try:
        project = Project.query.get(project_id)
        if not project or not project.domain_name:
            flash('Domain not found', 'error')
            return redirect(url_for('domains'))
        
        domain = project.domain_name
        
        # Remove Nginx configuration
        config_path = f'/etc/nginx/sites-available/{domain}'
        symlink_path = f'/etc/nginx/sites-enabled/{domain}'
        
        if os.path.exists(config_path):
            os.remove(config_path)
        if os.path.exists(symlink_path):
            os.remove(symlink_path)
        
        # Remove domain from project
        project.domain_name = None
        db.session.commit()
        
        # Reload Nginx
        success, message = reload_nginx()
        if not success:
            flash(f'Failed to reload Nginx: {message}', 'error')
            return redirect(url_for('domains'))
        
        flash('Domain removed successfully', 'success')
        
    except Exception as e:
        flash(f'Error removing domain: {str(e)}', 'error')
    
    return redirect(url_for('domains'))

@app.route('/domains/verify/<int:project_id>')
def verify_domain(project_id):
    try:
        project = Project.query.get(project_id)
        if not project or not project.domain_name:
            flash('Domain not found', 'error')
            return redirect(url_for('domains'))
        
        # Check if the project is running
        if not project.is_deployed:
            flash('Project must be deployed before verifying domain', 'warning')
            return redirect(url_for('domains'))
        
        # Verify Nginx configuration
        success, message = reload_nginx()
        if not success:
            flash(f'Domain verification failed: {message}', 'error')
            return redirect(url_for('domains'))
        
        flash('Domain verified successfully', 'success')
        
    except Exception as e:
        flash(f'Error verifying domain: {str(e)}', 'error')
    
    return redirect(url_for('domains'))










if __name__ == '__main__':
    app.run(debug=False,port=5001)

