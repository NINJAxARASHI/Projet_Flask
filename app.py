from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
import uuid
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import hmac
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cloud.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    storage_limit = db.Column(db.BigInteger, default=5 * 1024 * 1024 * 1024)  # 5GB default
    last_login = db.Column(db.DateTime)
    files = db.relationship('File', backref='owner', lazy=True)
    folders = db.relationship('Folder', backref='owner', lazy=True)
    groups = db.relationship('Group', secondary='user_groups', backref=db.backref('users', lazy='dynamic'))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='folder', lazy=True)
    children = db.relationship('Folder', backref=db.backref('parent', remote_side=[id]))
    size_limit = db.Column(db.BigInteger)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(128))
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_starred = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), nullable=False, default='complete')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)  # Message chiffré avec AES
    encrypted_aes_key = db.Column(db.Text, nullable=False)  # Clé AES chiffrée avec RSA
    encrypted_hmac_key = db.Column(db.Text, nullable=False)  # Clé HMAC chiffrée avec RSA
    iv = db.Column(db.Text, nullable=False)  # Vecteur d'initialisation pour AES
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    signature = db.Column(db.Text, nullable=False)  # Signature du message
    hmac = db.Column(db.Text, nullable=False)  # HMAC pour vérifier l'intégrité
    original_content = db.Column(db.Text)  # Message original pour l'expéditeur
    is_deleted_for_receiver = db.Column(db.Boolean, default=False)  # Indique si le message est supprimé pour le destinataire
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

# Table d'association pour la relation many-to-many entre User et Group
user_groups = db.Table('user_groups',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    to_all = db.Column(db.Boolean, default=False)
    groups = db.relationship('Group', secondary='announcement_groups', backref=db.backref('announcements', lazy='dynamic'))
    author = db.relationship('User', backref='announcements')

# Table d'association entre Announcement et Group
announcement_groups = db.Table('announcement_groups',
    db.Column('announcement_id', db.Integer, db.ForeignKey('announcement.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user, remember=remember, duration=timedelta(days=30) if remember else None)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        
        flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Vous n\'avez pas les droits d\'accès à cette page.', 'error')
        return render_template('user_dashboard.html')
    return render_template('dashboard_admin.html')

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('user_dashboard.html')

@app.route('/browse')
@app.route('/browse/<int:folder_id>')
@login_required
def browse(folder_id=None):
    try:
        # Récupérer le dossier courant et ses sous-dossiers
        current_folder = None
        subfolders = []
        files = []
        available_folders = []
        root_folder = None
        
        if folder_id:
            # Si un dossier spécifique est demandé
            if current_user.is_admin:
                # Les admins peuvent accéder à tous les dossiers
                current_folder = Folder.query.get_or_404(folder_id)
                subfolders = Folder.query.filter_by(parent_id=folder_id).all()
                files = File.query.filter_by(folder_id=folder_id).all()
            else:
                # Les utilisateurs normaux ne peuvent accéder qu'à leurs dossiers
                current_folder = Folder.query.filter_by(id=folder_id, owner_id=current_user.id).first_or_404()
                subfolders = Folder.query.filter_by(parent_id=folder_id, owner_id=current_user.id).all()
                files = File.query.filter_by(folder_id=folder_id, owner_id=current_user.id).all()
        else:
            # Si aucun dossier n'est sélectionné
            if current_user.is_admin:
                # Les admins voient tous les dossiers racine et le dossier root
                root_folder = Folder.query.filter_by(name='root', parent_id=None).first()
                if not root_folder:
                    # Créer le dossier root s'il n'existe pas
                    root_folder = Folder(name='root', owner_id=current_user.id)
                    db.session.add(root_folder)
                    db.session.commit()
                available_folders = Folder.query.filter(Folder.parent_id.is_(None), Folder.id != root_folder.id).all()
            else:
                # Les utilisateurs normaux ne voient que leurs dossiers racine
                available_folders = Folder.query.filter_by(parent_id=None, owner_id=current_user.id).all()
        
        # Récupérer le chemin du dossier courant
        folder_path = []
        if current_folder:
            folder = current_folder
            while folder:
                folder_path.insert(0, folder)
                folder = folder.parent
        
        return render_template('browse.html', 
                             current_folder=current_folder,
                             subfolders=subfolders,
                             files=files,
                             folder_path=folder_path,
                             available_folders=available_folders,
                             root_folder=root_folder)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('browse.html', 
                             current_folder=None,
                             subfolders=[],
                             files=[],
                             folder_path=[],
                             available_folders=[],
                             root_folder=None)

@app.route('/upload')
@login_required
def upload():
    try:
        folders = Folder.query.filter_by(owner_id=current_user.id).all()
        
        # Récupérer les uploads en cours et terminés
        try:
            uploads_in_progress = File.query.filter_by(owner_id=current_user.id, status='in_progress').all()
            completed_uploads = File.query.filter_by(owner_id=current_user.id, status='complete').limit(5).all()
        except:
            uploads_in_progress = []
            completed_uploads = File.query.filter_by(owner_id=current_user.id).limit(5).all()
        
        # Calculer l'utilisation du stockage
        used_storage = sum(f.size for f in current_user.files)
        total_storage = current_user.storage_limit
        storage_percentage = round((used_storage / total_storage) * 100) if total_storage > 0 else 0
        
        # Formatage pour l'affichage
        if used_storage < 1024**2:
            used_storage_formatted = f"{used_storage/1024:.1f} KB"
        elif used_storage < 1024**3:
            used_storage_formatted = f"{used_storage/(1024**2):.1f} MB"
        else:
            used_storage_formatted = f"{used_storage/(1024**3):.1f} GB"
        
        if total_storage < 1024**3:
            total_storage_formatted = f"{total_storage/(1024**2):.1f} MB"
        else:
            total_storage_formatted = f"{total_storage/(1024**3):.1f} GB"
        
        return render_template('upload.html',
                             folders=folders,
                             uploads_in_progress=uploads_in_progress,
                             completed_uploads=completed_uploads,
                             used_storage=used_storage_formatted,
                             total_storage=total_storage_formatted,
                             storage_percentage=storage_percentage)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('upload.html',
                             folders=[],
                             uploads_in_progress=[],
                             completed_uploads=[],
                             used_storage="0 B",
                             total_storage="0 B",
                             storage_percentage=0)

@app.route('/api/files/upload', methods=['POST'])
@login_required
def upload_file():
    if 'files[]' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})

    files = request.files.getlist('files[]')
    folder_id = request.form.get('folder_id', type=int)
    
    # Make folder_id optional
    if folder_id:
        folder = Folder.query.get_or_404(folder_id)
        if folder.owner_id != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'message': 'Access denied'})

    used_storage = sum(f.size for f in current_user.files)
    
    uploaded_files = []
    for file in files:
        if file.filename == '':
            continue
            
        file_size = len(file.read())
        file.seek(0)  # Reset file pointer
        
        if used_storage + file_size > current_user.storage_limit:
            return jsonify({'success': False, 'message': 'Storage limit exceeded'})
            
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            file.save(file_path)
            new_file = File(
                name=filename,
                filename=unique_filename,
                size=file_size,
                mime_type=file.content_type,
                folder_id=folder_id,
                owner_id=current_user.id,
                status='complete'
            )
            db.session.add(new_file)
            db.session.commit()  # Commit each file individually to get ID
            uploaded_files.append(new_file)  # Add the file object to the list
            used_storage += file_size
            
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})

    try:
        return jsonify({
            'success': True,
            'message': f"Successfully uploaded {len(uploaded_files)} files",
            'files': [{
                'id': f.id,
                'name': f.name,
                'size': f.size,
                'status': 'complete'
            } for f in uploaded_files]
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})
    
@app.route('/api/files/status', methods=['GET'])
@login_required
def get_upload_status():
    try:
        uploads = File.query.filter_by(owner_id=current_user.id).order_by(File.created_at.desc()).limit(10).all()
        
        return jsonify({
            'success': True,
            'uploads': [{
                'id': f.id,
                'name': f.name,
                'size': f.size,
                'status': getattr(f, 'status', 'complete'),  # Use getattr to safely get status
                'progress': 100 if getattr(f, 'status', 'complete') == 'complete' else 70
            } for f in uploads]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.owner_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        db.session.delete(file)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/files/<int:file_id>/cancel', methods=['POST'])
@login_required
def cancel_upload(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.owner_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        db.session.delete(file)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/files/<int:file_id>/pause', methods=['POST'])
@login_required
def pause_upload(file_id):
    try:
        file = File.query.get_or_404(file_id)
        
        if file.owner_id != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'message': 'Access denied'}), 403

        try:
            file.status = 'paused'
            db.session.commit()
            return jsonify({'success': True})
        except:
            # Si la colonne status n'existe pas, on renvoie quand même un succès
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/files/<int:file_id>/resume', methods=['POST'])
@login_required
def resume_upload(file_id):
    try:
        file = File.query.get_or_404(file_id)
        
        if file.owner_id != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'message': 'Access denied'}), 403

        try:
            file.status = 'in_progress'
            db.session.commit()
            return jsonify({'success': True})
        except:
            # Si la colonne status n'existe pas, on renvoie quand même un succès
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/folders', methods=['POST'])
@login_required
def create_folder():
    try:
        data = request.get_json()
        name = data.get('name')
        parent_id = data.get('parent_id')
        size_limit = data.get('size_limit')  # Nouveau paramètre pour la limite de taille
        
        if not name:
            return jsonify({'success': False, 'message': 'Folder name is required'})
            
        # Vérifier si le dossier parent existe
        if parent_id is not None and parent_id != "null":
            parent = Folder.query.get_or_404(parent_id)
            if parent.owner_id != current_user.id and not current_user.is_admin:
                return jsonify({'success': False, 'message': 'Access denied'})
        
        # Créer le nouveau dossier
        new_folder = Folder(
            name=name,
            parent_id=parent_id if parent_id not in [None, "null"] else None,
            owner_id=current_user.id,
            size_limit=size_limit if current_user.is_admin else None  # Seul l'admin peut définir une limite
        )
        
        db.session.add(new_folder)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Folder created successfully',
            'folder': {
                'id': new_folder.id,
                'name': new_folder.name,
                'size_limit': new_folder.size_limit
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.owner_id != current_user.id and not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('browse'))

    return send_file(
        os.path.join(app.config['UPLOAD_FOLDER'], file.filename),
        download_name=file.name,
        as_attachment=True
    )

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Vous n\'avez pas les droits d\'accès à cette page.', 'error')
        return render_template('user_dashboard.html')
    
    users = User.query.all()
    total_files = File.query.count()
    total_storage_used = db.session.query(db.func.sum(File.size)).scalar() or 0
    
    return render_template('admin.html',
                         users=users,
                         total_files=total_files,
                         total_storage_used=total_storage_used)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Ici vous pouvez ajouter la logique pour envoyer un email de réinitialisation
            # Pour l'instant, on simule juste une réponse positive
            flash('If an account exists with this email, you will receive password reset instructions.', 'info')
            return redirect(url_for('login'))
        
        # Même si l'utilisateur n'existe pas, on renvoie le même message pour des raisons de sécurité
        flash('If an account exists with this email, you will receive password reset instructions.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        group_ids = request.form.getlist('groups')
        to_all = 'to_all' in request.form
        if title and content:
            ann = Announcement(title=title, content=content, author_id=current_user.id, to_all=to_all)
            if not to_all and group_ids:
                groups = Group.query.filter(Group.id.in_(group_ids)).all()
                ann.groups = groups
            db.session.add(ann)
            db.session.commit()
            flash('Annonce publiée !', 'success')
        else:
            flash('Titre et contenu requis.', 'error')
        return redirect(url_for('report'))
    # Afficher les annonces visibles pour l'utilisateur
    user_group_ids = [g.id for g in current_user.groups] if hasattr(current_user, 'groups') else []
    announcements = Announcement.query.filter(
        (Announcement.to_all == True) |
        (Announcement.groups.any(Group.id.in_(user_group_ids))) |
        (Announcement.author_id == current_user.id)
    ).order_by(Announcement.created_at.desc()).all()
    all_groups = Group.query.all()
    return render_template('announcements.html', announcements=announcements, all_groups=all_groups)

@app.route('/contact_us', methods=['GET', 'POST'])
@login_required
def contact_us():
    if request.method == 'POST':
        try:
            subject = request.form.get('subject')
            message = request.form.get('message')
            
            if not subject or not message:
                flash('Subject and message are required', 'error')
                return redirect(url_for('contact_us'))
            
            # Ici, vous pouvez ajouter la logique pour envoyer l'email
            # Par exemple, en utilisant Flask-Mail ou un autre service
            
            flash('Your message has been sent successfully', 'success')
            return redirect(url_for('admin_dashboard' if current_user.is_admin else 'user_dashboard'))
            
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('contact_us'))
    
    return render_template('contact_us.html')

@app.route('/admin/panel')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Vous n\'avez pas les droits d\'accès à cette page.', 'error')
        return render_template('user_dashboard.html')
    
    try:
        # Récupération des données pour le panneau d'administration
        users = User.query.all()
        total_files = File.query.count()
        total_folders = Folder.query.count()
        total_storage_used = db.session.query(db.func.sum(File.size)).scalar() or 0
        
        # Formatage de la taille totale
        if total_storage_used < 1024:
            total_storage_formatted = f"{total_storage_used} B"
        elif total_storage_used < 1024**2:
            total_storage_formatted = f"{total_storage_used/1024:.1f} KB"
        elif total_storage_used < 1024**3:
            total_storage_formatted = f"{total_storage_used/(1024**2):.1f} MB"
        else:
            total_storage_formatted = f"{total_storage_used/(1024**3):.1f} GB"
        
        # Calcul de l'utilisation du stockage par utilisateur
        user_storage = []
        for user in users:
            user_files = File.query.filter_by(owner_id=user.id).all()
            storage_used = sum(f.size for f in user_files)
            
            # Formatage pour l'affichage
            if storage_used < 1024**2:
                storage_formatted = f"{storage_used/1024:.1f} KB"
            elif storage_used < 1024**3:
                storage_formatted = f"{storage_used/(1024**2):.1f} MB"
            else:
                storage_formatted = f"{storage_used/(1024**3):.1f} GB"
                
            user_storage.append({
                'id': user.id,
                'email': user.email,
                'storage_used': storage_formatted,
                'storage_limit': f"{user.storage_limit/(1024**3):.1f} GB",
                'usage_percent': round((storage_used / user.storage_limit) * 100, 2) if user.storage_limit > 0 else 0
            })
        
        return render_template('admin_panel.html',
                             users=users,
                             user_storage=user_storage,
                             total_users=len(users),
                             total_files=total_files,
                             total_folders=total_folders,
                             total_storage=total_storage_formatted)
    except Exception as e:
        flash(f'Une erreur est survenue: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/users', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_users():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    if request.method == 'GET':
        users = User.query.all()
        return jsonify({
            'success': True,
            'users': [{
                'id': user.id,
                'email': user.email,
                'is_admin': user.is_admin,
                'storage_limit': user.storage_limit,
                'last_login': user.last_login.isoformat() if user.last_login else None
            } for user in users]
        })
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            is_admin = data.get('is_admin', False)
            storage_limit = data.get('storage_limit', 5 * 1024 * 1024 * 1024)  # 5GB par défaut
            
            if not email or not password:
                return jsonify({'success': False, 'message': 'Email and password are required'})
            
            if User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'message': 'Email already exists'})
            
            # Créer le nouvel utilisateur
            new_user = User(
                email=email,
                is_admin=is_admin,
                storage_limit=storage_limit
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.flush()  # Pour obtenir l'ID de l'utilisateur avant le commit
            
            # Générer une nouvelle paire de clés RSA
            private_key, public_key = generate_rsa_keys()
            
            # Sauvegarder uniquement les clés RSA
            save_rsa_keys(new_user.id, private_key, public_key)
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'User created successfully with RSA keys',
                'user': {
                    'id': new_user.id,
                    'email': new_user.email,
                    'is_admin': new_user.is_admin,
                    'storage_limit': new_user.storage_limit
                }
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})

    try:
        user = User.query.get_or_404(user_id)

        if user.is_admin:
            return jsonify({'success': False, 'message': 'Cannot delete an admin user'})

        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'})

        db.session.delete(user)
        db.session.commit()

        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
@login_required
def delete_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    
    # Vérifier les permissions
    if folder.owner_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    try:
        # Fonction récursive pour supprimer les fichiers et sous-dossiers
        def delete_folder_contents(folder):
            # Supprimer les fichiers du dossier
            for file in folder.files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                db.session.delete(file)
            
            # Supprimer récursivement les sous-dossiers
            for subfolder in folder.children:
                delete_folder_contents(subfolder)
                db.session.delete(subfolder)
        
        # Supprimer le contenu du dossier et le dossier lui-même
        delete_folder_contents(folder)
        db.session.delete(folder)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/messagerie')
@login_required
def messagerie():
    # Récupérer tous les utilisateurs pour la liste des contacts
    users = User.query.filter(User.id != current_user.id).all()
    
    # Récupérer les conversations récentes
    conversations = db.session.query(
        Message,
        User
    ).join(
        User,
        ((Message.sender_id == User.id) & (Message.receiver_id == current_user.id)) |
        ((Message.receiver_id == User.id) & (Message.sender_id == current_user.id))
    ).order_by(Message.created_at.desc()).all()
    
    # Organiser les conversations par utilisateur
    chat_partners = {}
    
    # D'abord, ajouter tous les utilisateurs comme partenaires potentiels
    for user in users:
        chat_partners[user.id] = {
            'user': user,
            'last_message': None,
            'unread_count': 0
        }
    
    # Ensuite, mettre à jour avec les conversations existantes
    for message, user in conversations:
        partner_id = user.id
        if partner_id in chat_partners:
            if not chat_partners[partner_id]['last_message'] or message.created_at > chat_partners[partner_id]['last_message'].created_at:
                chat_partners[partner_id]['last_message'] = message
            if not message.is_read and message.receiver_id == current_user.id:
                chat_partners[partner_id]['unread_count'] += 1
    
    # Convertir le dictionnaire en liste et trier par date du dernier message
    chat_partners_list = list(chat_partners.values())
    chat_partners_list.sort(key=lambda x: x['last_message'].created_at if x['last_message'] else datetime.min, reverse=True)
    
    return render_template('messagerie.html', 
                         users=users,
                         chat_partners=chat_partners_list)

def generate_hmac(message, key):
    """Génère un HMAC pour vérifier l'intégrité du message"""
    h = hmac.new(key, message.encode(), hashlib.sha256)
    return base64.b64encode(h.digest()).decode()

def verify_hmac(message, hmac_value, key):
    """Vérifie l'intégrité du message avec le HMAC"""
    expected_hmac = generate_hmac(message, key)
    return hmac.compare_digest(hmac_value, expected_hmac)

def sign_message(message, private_key_pem):
    """Signe un message avec la clé privée RSA"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        message.encode(),
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode()

def verify_signature(message, signature, public_key_pem):
    """Vérifie la signature d'un message avec la clé publique RSA"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

@app.route('/api/messages', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.get_json()
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        
        if not receiver_id or not content:
            return jsonify({'success': False, 'message': 'Missing required fields'})
        
        # Vérifier si le destinataire existe
        receiver = User.query.get_or_404(receiver_id)
        
        # Vérifier que l'utilisateur ne s'envoie pas un message à lui-même
        if receiver_id == current_user.id:
            return jsonify({'success': False, 'message': 'Cannot send message to yourself'})
        
        # 1. Génération des clés pour ce message
        message_aes_key = generate_random_aes_key()  # Clé AES pour chiffrer le message
        hmac_key = os.urandom(32)  # Clé HMAC séparée pour vérifier l'intégrité
        iv = generate_random_iv()  # Vecteur d'initialisation pour AES
        
        # 2. Préparation du message
        timestamp = datetime.utcnow().isoformat()
        message_with_timestamp = f"{content}|{timestamp}"
        
        # 3. Génération du HMAC pour vérifier l'intégrité
        message_hmac = generate_hmac(message_with_timestamp, hmac_key)
        
        # 4. Chiffrement du message avec AES
        encrypted_content = encrypt_with_aes(message_with_timestamp, message_aes_key, iv)
        
        # 5. Récupération des clés RSA
        receiver_public_key = get_user_public_key(receiver_id)
        sender_private_key = get_user_private_key(current_user.id)
        
        if not receiver_public_key or not sender_private_key:
            return jsonify({'success': False, 'message': 'Missing encryption keys'})
        
        # 6. Chiffrement des clés symétriques avec la clé publique du destinataire
        encrypted_aes_key = encrypt_with_rsa(message_aes_key, receiver_public_key)
        encrypted_hmac_key = encrypt_with_rsa(hmac_key, receiver_public_key)
        
        # 7. Signature du message avec la clé privée de l'expéditeur
        message_signature = sign_message(message_with_timestamp, sender_private_key)
        
        # 8. Création du message dans la base de données
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            encrypted_content=encrypted_content,
            encrypted_aes_key=encrypted_aes_key,
            encrypted_hmac_key=encrypted_hmac_key,
            iv=iv,
            signature=message_signature,
            hmac=message_hmac,
            original_content=content  # Stocker le message original pour l'expéditeur
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': {
                'id': message.id,
                'sender_id': message.sender_id,
                'content': content,
                'created_at': message.created_at.strftime('%H:%M'),
                'is_read': message.is_read
            }
        })
    except Exception as e:
        print(f"Error sending message: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/messages/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(message_id):
    try:
        # Récupérer le message
        message = Message.query.get_or_404(message_id)
        
        # Vérifier que l'utilisateur est bien l'expéditeur
        if message.sender_id != current_user.id:
            return jsonify({
                'success': False,
                'message': 'Vous n\'êtes pas autorisé à supprimer ce message'
            }), 403
        
        # Supprimer le message de la base de données
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Message supprimé pour les deux utilisateurs'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/messages/<int:user_id>', methods=['GET'])
@login_required
def get_messages(user_id):
    try:
        # Vérifier que l'utilisateur demandé existe
        other_user = User.query.get_or_404(user_id)
        
        # Récupérer les messages
        messages = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.created_at).all()
        
        # Marquer les messages comme lus
        for message in messages:
            if message.receiver_id == current_user.id and not message.is_read:
                message.is_read = True
        db.session.commit()
        
        # Déchiffrer les messages
        decrypted_messages = []
        for message in messages:
            try:
                # Si on est le destinataire et que le message a été supprimé, on le saute
                if message.receiver_id == current_user.id and message.is_deleted_for_receiver:
                    continue
                    
                if message.sender_id == current_user.id:
                    # Si on est l'expéditeur, utiliser le message original
                    content = message.original_content
                else:
                    # Si on est le destinataire
                    private_key = get_user_private_key(current_user.id)
                    public_key = get_user_public_key(user_id)
                    
                    # Déchiffrer le message
                    aes_key = decrypt_with_rsa(message.encrypted_aes_key, private_key)
                    decrypted_content = decrypt_with_aes(
                        message.encrypted_content,
                        aes_key,
                        message.iv
                    )
                    
                    # Vérifier la signature
                    if not verify_signature(decrypted_content, message.signature, public_key):
                        print(f"Invalid signature for message {message.id}")
                        continue
                    
                    # Vérifier l'intégrité avec HMAC
                    hmac_key = decrypt_with_rsa(message.encrypted_hmac_key, private_key)
                    if not verify_hmac(decrypted_content, message.hmac, hmac_key):
                        print(f"Invalid HMAC for message {message.id}")
                        continue
                    
                    content, timestamp = decrypted_content.split('|')
                
                decrypted_messages.append({
                    'id': message.id,
                    'sender_id': message.sender_id,
                    'content': content,
                    'created_at': message.created_at.strftime('%H:%M'),
                    'is_read': message.is_read,
                    'is_deleted_for_receiver': message.is_deleted_for_receiver
                })
            except Exception as e:
                print(f"Error processing message {message.id}: {str(e)}")
                continue
        
        return jsonify({'success': True, 'messages': decrypted_messages})
    except Exception as e:
        print(f"Error in get_messages: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/messages/unread', methods=['GET'])
@login_required
def get_unread_count():
    count = Message.query.filter_by(
        receiver_id=current_user.id,
        is_read=False
    ).count()
    
    return jsonify({'success': True, 'count': count})

# Ajouter une fonction pour initialiser les clés RSA pour les utilisateurs existants
def initialize_missing_rsa_keys():
    try:
        users = User.query.all()
        for user in users:
            # Vérifier si l'utilisateur a déjà des clés RSA
            if not get_user_public_key(user.id):
                # Générer une nouvelle paire de clés RSA
                private_key, public_key = generate_rsa_keys()
                
                # Sauvegarder les clés RSA
                save_rsa_keys(user.id, private_key, public_key)
                
                print(f"Initialized RSA keys for user {user.email}")
    except Exception as e:
        print(f"Error initializing RSA keys: {str(e)}")

def generate_rsa_keys():
    """Génère une paire de clés RSA (publique/privée)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Sérialiser les clés
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode(), public_pem.decode()

def save_rsa_keys(user_id, private_key, public_key):
    """Sauvegarde les clés RSA d'un utilisateur"""
    # Créer le dossier keys s'il n'existe pas
    if not os.path.exists('keys'):
        os.makedirs('keys')
    
    # Sauvegarder la clé privée
    with open(f'keys/private_key_{user_id}.pem', 'w') as f:
        f.write(private_key)
    
    # Sauvegarder la clé publique
    with open(f'keys/public_key_{user_id}.pem', 'w') as f:
        f.write(public_key)

def get_user_public_key(user_id):
    """Récupère la clé publique d'un utilisateur"""
    try:
        with open(f'keys/public_key_{user_id}.pem', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return None

def get_user_private_key(user_id):
    """Récupère la clé privée d'un utilisateur"""
    try:
        with open(f'keys/private_key_{user_id}.pem', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return None

def generate_random_aes_key():
    """Génère une clé AES aléatoire"""
    return os.urandom(32)  # 256 bits

def generate_random_iv():
    """Génère un vecteur d'initialisation aléatoire pour AES"""
    return os.urandom(16)  # 128 bits

def encrypt_with_aes(data, key, iv):
    """Chiffre des données avec AES"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Padding des données
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

def decrypt_with_aes(encrypted_data, key, iv):
    """Déchiffre des données avec AES"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    encrypted_bytes = base64.b64decode(encrypted_data)
    padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
    
    # Unpadding des données
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode()

def encrypt_with_rsa(data, public_key_pem):
    """Chiffre des données avec une clé publique RSA"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    encrypted = public_key.encrypt(
        data if isinstance(data, bytes) else data.encode(),
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(encrypted).decode()

def decrypt_with_rsa(encrypted_data, private_key_pem):
    """Déchiffre des données avec une clé privée RSA"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted

def get_or_create_user_keys(user_id):
    """Récupère ou crée les clés RSA d'un utilisateur"""
    private_key = get_user_private_key(user_id)
    public_key = get_user_public_key(user_id)
    
    if not private_key or not public_key:
        private_key, public_key = generate_rsa_keys()
        save_rsa_keys(user_id, private_key, public_key)
    
    return public_key, private_key

@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
def reset_user_password(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        new_password = data.get('new_password')
        
        if not new_password:
            return jsonify({'success': False, 'message': 'New password is required'})
        
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Password reset successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/groups', methods=['GET', 'POST'])
@login_required
def manage_groups():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    if request.method == 'GET':
        groups = Group.query.all()
        return jsonify({
            'success': True,
            'groups': [{
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'user_count': group.users.count()
            } for group in groups]
        })
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            name = data.get('name')
            description = data.get('description', '')
            
            if not name:
                return jsonify({'success': False, 'message': 'Group name is required'})
            
            existing_group = Group.query.filter_by(name=name).first()
            if existing_group:
                return jsonify({'success': False, 'message': 'Group name already exists'})
            
            new_group = Group(name=name, description=description)
            db.session.add(new_group)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Group created successfully',
                'group': {
                    'id': new_group.id,
                    'name': new_group.name,
                    'description': new_group.description
                }
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/groups/<int:group_id>/users', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_group_users(group_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    group = Group.query.get_or_404(group_id)
    
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'users': [{
                'id': user.id,
                'email': user.email
            } for user in group.users]
        })
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            user_id = data.get('user_id')
            
            if not user_id:
                return jsonify({'success': False, 'message': 'User ID is required'})
            
            user = User.query.get_or_404(user_id)
            if user in group.users:
                return jsonify({'success': False, 'message': 'User is already in this group'})
            
            group.users.append(user)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'User added to group successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})
    
    elif request.method == 'DELETE':
        try:
            data = request.get_json()
            user_id = data.get('user_id')
            
            if not user_id:
                return jsonify({'success': False, 'message': 'User ID is required'})
            
            user = User.query.get_or_404(user_id)
            if user not in group.users:
                return jsonify({'success': False, 'message': 'User is not in this group'})
            
            group.users.remove(user)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'User removed from group successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    with app.app_context():
        print("Initializing database...")
        # Vérifier si la base de données existe
        if not os.path.exists('cloud.db'):
            print("Creating new database...")
            # Créer toutes les tables
            db.create_all()
            
            print("Creating default users...")
            # Initialize default users if they don't exist
            if not User.query.filter_by(email='user@example.com').first():
                # Create normal user
                user = User(email='user@example.com')
                user.set_password('user123')
                user.is_admin = False
                user.storage_limit = 2 * 1024 * 1024 * 1024  # 2GB
                db.session.add(user)
                print("Created normal user: user@example.com")

                # Create admin user
                admin = User(email='admin@example.com')
                admin.set_password('admin123')
                admin.is_admin = True
                admin.storage_limit = 5 * 1024 * 1024 * 1024  # 5GB
                db.session.add(admin)
                print("Created admin user: admin@example.com")
                
                db.session.commit()
                print("Users committed to database")
                
                print("Initializing RSA keys for users...")
                # Initialiser les clés RSA pour les utilisateurs par défaut
                initialize_missing_rsa_keys()
                print("RSA keys initialized")
        else:
            print("Database already exists, skipping initialization...")
            # Vérifier et créer les tables si elles n'existent pas
            db.create_all()
    
    print("Starting Flask application...")
    app.run(debug=True)