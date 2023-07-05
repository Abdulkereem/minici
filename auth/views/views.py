from flask import Blueprint, render_template
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/migrate')
def migrate():
    # Create the database tables
    db.drop_all()
    db.create_all()


@auth_bp.route('/seed/<email>')
def seed(email: str):
    import os
    new_user = User(username=email, password=generate_random_password())
    db.session.add(new_user)
    db.session.commit()
    return new_user.password


@auth_bp.route('/')
@login_required
def dashboard():
    projects = Project.query.all()
    return render_template('dashboard.html', projects=projects)