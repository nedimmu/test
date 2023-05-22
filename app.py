from uuid import NAMESPACE_DNS
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, Namespace, emit, join_room, leave_room
import logging
from sqlalchemy.exc import SQLAlchemyError
from flask_migrate import Migrate
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized, oauth_error


# Create a logger object
logger = logging.getLogger(__name__)

# Set the log level you want
logger.setLevel(logging.DEBUG)

# Create a console handler
ch = logging.StreamHandler()

# Set the level for this handler
ch.setLevel(logging.DEBUG)

# Create a formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Add the formatter to the handler
ch.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(ch)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to your own secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database11.db'  # SQLite database file
app.config['GOOGLE_OAUTH_CLIENT_ID'] = '950750281131-ut9gkklhtj8ebmj7mg32sdjco5mgrfjq.apps.googleusercontent.com'
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = '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'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class MyNamespace(Namespace):
    def on_connect(self):
        print('Client connected')

    def on_disconnect(self):
        print('Client disconnected')

    def on_custom_event(self, data):
        print('Received custom event:', data)
        self.emit('response', 'This is a response')

socketio = SocketIO(app, logger=True, engineio_logger=True)
socketio.on_namespace(MyNamespace('/mynamespace'))


migrate = Migrate(app, db)


# User model
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    google_id = db.Column(db.String(100), unique=True)
    google_token = db.Column(db.String(500))
    google_token_expiration = db.Column(db.DateTime)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Note(db.Model):
    __tablename__ = 'notes'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)

    project = db.relationship('Project', backref=db.backref('notes', lazy=True))

class Projectmember(db.Model):
    __tablename__ = 'projectmembers'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    project = db.relationship('Project', backref=db.backref('projectmembers', lazy=True))
    member = db.relationship('User', backref=db.backref('projectmembers', lazy=True))

redirect_url = "http://127.0.0.1:5000/google-login"

google_blueprint = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    scope=["profile", "email"],
    offline=True,
    redirect_url=redirect_url
)

app.register_blueprint(google_blueprint, url_prefix="/login")


@app.route("/google-login")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        user_data = resp.json()
        # Process the user data and create or authenticate the user
        # ...
        return redirect(url_for("profile"))  # Redirect to the desired page
    flash("Failed to retrieve user data from Google.")
    return redirect(url_for("login"))  # Redirect to the login page

@oauth_authorized.connect_via(google_blueprint)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.")
        return redirect(url_for("login"))

    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        user_data = resp.json()
        # Process the user data and create or authenticate the user
        # ...
        return redirect(url_for("projects"))
    else:
        flash("Failed to retrieve user data from Google.")
        return redirect(url_for("login"))

@oauth_error.connect_via(google_blueprint)
def google_error(blueprint, error, error_description=None, error_uri=None):
    flash(f"OAuth error from {blueprint.name}: {error_description}")
    return redirect(url_for("login"))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@socketio.on('add_note')
def handle_add_note(data):
    print('received data:', data)
    logger.debug(f'Received add_note event with data: {data}')

    try:
        # Create a new note instance
        new_note = Note(content=data["data"], project_id=int(data["project_id"]))
        db.session.add(new_note)
        db.session.commit()

        logger.debug('New note added to database')

        # Emit event to update client in the project room
        emit('new_note', { 'id': new_note.id, 'content': new_note.content }, room=f'project_{data["project_id"]}')

    except SQLAlchemyError as e:
        # Something went wrong during commit
        print(str(e))
        logger.error(f'Error while adding new note: {str(e)}')
        emit('new_note', {'data': 'Note could not be added', 'content': '', 'project_id': ''}, broadcast=True)

# Routes
@app.route('/')
def home():
    return 'Welcome to the Home Page'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        
        return redirect(url_for('add_project'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('projects'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        login_user(user)
        
        return redirect(url_for('projects'))

    return render_template('login.html')

@app.route('/projects')
@login_required
def projects():
    user = current_user
    user_projects = Project.query.filter_by(user_id=user.id).all()
    project_memberships = Projectmember.query.filter_by(member_id=user.id).all()

    # Fetch the projects the user is added to as a member
    member_projects = [pm.project for pm in project_memberships]

    # Check if a project was selected and set it as the current project
    selected_project_id = request.args.get('project_id')
    if selected_project_id:
        selected_project = Project.query.get(selected_project_id)
        if selected_project and (selected_project.user_id == user.id or selected_project in member_projects):
            session['current_project_id'] = selected_project_id
        else:
            flash('Invalid project or unauthorized access')

    return render_template('projects.html', user=user, projects=user_projects, member_projects=member_projects)


@app.route('/profile/<int:project_id>', methods=['GET', 'POST'])
@login_required
def profile(project_id):
    project = Project.query.get(project_id)
    user = current_user
    project_memberships = Projectmember.query.filter_by(member_id=user.id).all()
    if project:
        if project.user_id == current_user.id or current_user in [pm.member for pm in project.projectmembers]:
            members = project.projectmembers
            if request.method == 'POST':
                if 'delete_member_id' in request.form:
                    member_id = int(request.form['delete_member_id'])
                    if member_id != current_user.id and (project.user_id == current_user.id or current_user in [pm.member for pm in project.projectmembers]):
                        member = Projectmember.query.get(member_id)
                        if member:
                            db.session.delete(member)
                            db.session.commit()
                            flash('Member deleted successfully')
                        else:
                            flash('Member not found')
                    else:
                        flash('You do not have permission to delete this member')

                elif 'content' in request.form:
                    content = request.form['content']
                    new_note = Note(content=content, project_id=project.id)
                    db.session.add(new_note)
                    db.session.commit()
                    flash('Note added successfully')


            notes = project.notes
            member_projects = [pm.project for pm in project_memberships]
            session['current_project_id'] = project.id

            return render_template('profile.html', project=project, members=members, notes=notes, member_projects=member_projects, project_id=project.id)

        flash('You do not have permission to access this project')
    else:
        flash('Project not found')

    return redirect(url_for('projects'))



@app.route('/add_signup', methods=['POST'])
@login_required
def add_signup():
    username = request.form.get('username')  # Use get() method to avoid KeyError
    project_id = request.form.get('project_id')

    if username and project_id:
        user = User.query.filter_by(username=username).first()
        project = Project.query.get(project_id)

        if user and project:
            existing_signup = Projectmember.query.filter_by(member_id=user.id, project_id=project.id).first()
            if existing_signup:
                flash('User is already a member of this project')
            else:
                new_signup = Projectmember(member_id=user.id, project_id=project.id)
                db.session.add(new_signup)
                db.session.commit()
                flash('User invited successfully')
        else:
            flash('Invalid username or project ID')
    else:
        flash('Missing username or project ID')

    return redirect(url_for('profile', project_id=project_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/add_project', methods=['GET', 'POST'])
@login_required
def add_project():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        new_project = Project(title=title, description=description, user_id=current_user.id)
        db.session.add(new_project)
        db.session.commit()

        new_projectmember = Projectmember(project_id=new_project.id, member_id=current_user.id)
        db.session.add(new_projectmember)
        db.session.commit()

        # Save the project ID in the session
        session['current_project_id'] = new_project.id

        flash('Project added successfully')
        return redirect(url_for('profile', project_id=new_project.id))

    return render_template('add_project.html')

@app.route('/update_project_id', methods=['POST'])
def update_project_id():
  project_id = request.json['project_id']
  session['current_project_id'] = project_id
  return 'OK', 200


@socketio.on('connect')
@login_required
def handle_connect():
    try:
        user_id = current_user.id
        join_room(user_id)  # Join the room associated with the user's ID
        emit('user_connected', {'user_id': user_id}, broadcast=True)  # Broadcast user connected event
        logger.debug(f'User with ID {user_id} has connected.')
    except Exception as e:
        logger.error(f'Error during connect: {str(e)}')

@socketio.on('disconnect')
@login_required
def handle_disconnect():
    try:
        user_id = current_user.id
        leave_room(user_id)  # Leave the room associated with the user's ID
        socketio.emit('user_disconnected', {'user_id': user_id}, room='project_1')  # Broadcast user disconnected event
        logger.debug(f'User with ID {user_id} has disconnected.')
    except Exception as e:
        logger.error(f'Error during disconnect: {str(e)}')

@socketio.on('join_room')
def handle_join_room(data):
    try:
        project_id = data['project_id']
        join_room(f'project_{project_id}')
        logger.debug(f'User joined room project_{project_id}')
    except Exception as e:
        logger.error(f'Error during join_room: {str(e)}')

@socketio.on('leave_room')
def handle_leave_room(data):
    try:
        project_id = data['project_id']
        leave_room(f'project_{project_id}')
        logger.debug(f'User left room project_{project_id}')
    except Exception as e:
        logger.error(f'Error during leave_room: {str(e)}')

@socketio.on('delete_note')
def handle_delete_note(data):
    try:
        note_id = data['note_id']
        note_to_delete = Note.query.get(note_id)
        if note_to_delete:
            db.session.delete(note_to_delete)
            db.session.commit()
            emit('note_deleted', { 'note_id': note_id }, room=f'project_{data["project_id"]}')
            logger.debug(f'Note {note_id} deleted in project_{data["project_id"]}')
        else:
            logger.error(f'No note found with ID {note_id}')
    except Exception as e:
        logger.error(f'Error during delete_note: {str(e)}')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        db.session.commit()  # Commit any pending database changes before running migrations

    socketio.run(app)
