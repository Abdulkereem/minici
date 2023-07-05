from flask_sqlalchemy import SQLAlchemy


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