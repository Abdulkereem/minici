from flask import Flask, render_template, request, redirect, flash, jsonify, send_from_directory, url_for , send_file , session
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



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///projects.db'
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
db = SQLAlchemy(app)

DEFAULT_DIRECTORY = os.path.abspath("/")


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
    id                  = db.Column(db.Integer, primary_key=True)
    name                = db.Column(db.String(100))
    directory           = db.Column(db.String(100))
    deploy_commands     = db.Column(db.String(255))
    updated             = db.Column(db.Boolean, default=False)
    is_deployed         = db.Column(db.Boolean, default=False)
    github_token        = db.Column(db.String(255))  # Column for storing GitHub token
    git_repo            = db.Column(db.String(255))  # Column for storing GitHub token
    depoloy_triger      = db.Column(db.String(255))  # Column for storing GitHub token
    branch              = db.Column(db.String(255))  # Column for storing GitHub token
    domain_name         = db.Column(db.String(255))
    port                = db.Column(db.String(255))




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




if __name__ == '__main__':
    app.run(debug=True,port=5001)
