from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from datetime import datetime
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Assurez-vous que le dossier d'upload existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Fonction pour vérifier si l'extension de fichier est autorisée
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Fonction pour obtenir une connexion à la base de données
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    conn.row_factory = sqlite3.Row
    return conn

# Initialisation de la base de données si elle n'existe pas
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Création de la table users si elle n'existe pas
    # permissions structure  # [(id_folder_can_view) ,(id_folder_can_upload)  ,(id_folder_can_download)  ,(id_folder_can_delete)  ,(id_folder_can_create)]
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        permissions TEXT NOT NULL DEFAULT '[(),(),(),(),()]',
        storage_quota INTEGER DEFAULT 104857600, -- 100 MB par défaut
        max_folders INTEGER DEFAULT 10,
        max_files INTEGER DEFAULT 50,
        used_storage INTEGER DEFAULT 0
    )
    ''')
    
    # Création de la table folders
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        folder_name TEXT NOT NULL,
        parent_folder_id INTEGER,
        owner_id INTEGER NOT NULL,
        is_public INTEGER NOT NULL DEFAULT 0,
        created_date TIMESTAMP NOT NULL,
        folder_count INTEGER DEFAULT 0,
        file_count INTEGER DEFAULT 0,
        FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (parent_folder_id) REFERENCES folders (id) ON DELETE CASCADE
    )
    ''')
    
    
    # Modification de la table files pour inclure l'ID du dossier
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        folder_id INTEGER NOT NULL,
        uploaded_by INTEGER NOT NULL,
        upload_date TIMESTAMP NOT NULL,
        filesize INTEGER NOT NULL,
        FOREIGN KEY (uploaded_by) REFERENCES users (id),
        FOREIGN KEY (folder_id) REFERENCES folders (id) ON DELETE CASCADE
    )
    ''')
    
    # Vérifier si un admin existe déjà, sinon en créer un
    cursor.execute("SELECT * FROM users WHERE is_admin = 1")
    if not cursor.fetchone():
        admin_password = generate_password_hash('admin123')
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", 
                      ('admin', admin_password))
        
        # Récupérer l'ID de l'admin
        admin_id = cursor.lastrowid
        
        # Créer le dossier personnel de l'admin
        cursor.execute('''
        INSERT INTO folders (folder_name, parent_folder_id, owner_id, is_public, created_date)
        VALUES (?, NULL, ?, 0, ?)
        ''', ('admin', admin_id, datetime.now()))
    
    conn.commit()
    conn.close()

# Fonction pour vérifier si un utilisateur a accès à un dossier
def can_view(user_id, folder_id, permission_type='can_view'):
    conn = get_db_connection()
    
    # Si l'utilisateur est admin, il a accès à tout
    cursor = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    if user and user['is_admin'] == 1:
        conn.close()
        return True
    
    # Vérifier si l'utilisateur est le propriétaire du dossier
    cursor = conn.execute('SELECT owner_id, is_public FROM folders WHERE id = ?', (folder_id,))
    folder = cursor.fetchone()
    
    if not folder:
        conn.close()
        return False
    
    # Si l'utilisateur est le propriétaire, il a tous les droits
    if folder['owner_id'] == user_id:
        conn.close()
        return True
    
    # Si le dossier est public, vérifier les permissions spécifiques
    if folder['is_public'] == 1:
        conn.close()
        return True

    else:
        # Pour les dossiers privés, vérifier explicitement les permissions
        cursor = conn.execute(f'SELECT permissions FROM users WHERE id = ?', 
                             (user_id))
        permission = cursor.fetchone()
        
        if folder_id in eval(permission)[0]:
            conn.close()
            return True
    
    conn.close()
    return False

# Fonction pour créer le dossier personnel d'un utilisateur
def create_personal_folder(user_id, username):
    conn = get_db_connection()
    
    # Vérifier si l'utilisateur a déjà un dossier personnel
    cursor = conn.execute('''
    SELECT id FROM folders 
    WHERE owner_id = ? AND parent_folder_id IS NULL
    ''', (user_id,))
    
    existing_folder = cursor.fetchone()
    
    if not existing_folder:
        # Créer le dossier personnel (racine) pour l'utilisateur
        conn.execute('''
        INSERT INTO folders (folder_name, parent_folder_id, owner_id, is_public, created_date)
        VALUES (?, NULL, ?, 0, ?)
        ''', (username, user_id, datetime.now()))
        
        conn.commit()

    conn.close()

# Fonction pour vérifier si l'utilisateur n'a pas dépassé son quota
def check_quota(user_id, file_size=0, new_folder=False):
    conn = get_db_connection()
    
    # Récupérer les informations de quota de l'utilisateur
    cursor = conn.execute('''
    SELECT storage_quota, max_folders, max_files, used_storage 
    FROM users 
    WHERE id = ?
    ''', (user_id,))
    
    user = cursor.fetchone()
    
    # Vérifier si l'utilisateur peut ajouter un nouveau dossier
    if new_folder:
        # Compter le nombre de dossiers de l'utilisateur
        cursor = conn.execute('''
        SELECT COUNT(*) as folder_count 
        FROM folders 
        WHERE owner_id = ?
        ''', (user_id,))
        
        folder_count = cursor.fetchone()['folder_count']
        
        if folder_count >= user['max_folders']:
            conn.close()
            return False, "You have reached the maximum number of folders allowed."
    
    # Si on ajoute un fichier, vérifier la taille et le nombre
    if file_size > 0:
        # Vérifier si l'ajout du fichier dépasse le quota de stockage
        if user['used_storage'] + file_size > user['storage_quota']:
            conn.close()
            return False, "Your storage limit has been reached. Please free up space to continue uploading files."
        
        # Compter le nombre de fichiers de l'utilisateur
        cursor = conn.execute('''
        SELECT COUNT(*) as file_count 
        FROM files 
        WHERE uploaded_by = ?
        ''', (user_id,))
        
        file_count = cursor.fetchone()['file_count']
        
        if file_count >= user['max_files']:
            conn.close()
            return False, "You have reached the maximum number of files allowed"
    
    conn.close()
    return True, ""

# Fonction pour mettre à jour le stockage utilisé par l'utilisateur
def update_used_storage(user_id, file_size):
    conn = get_db_connection()
    conn.execute('''
    UPDATE users
    SET used_storage = used_storage + ?
    WHERE id = ?
    ''', (file_size, user_id))
    conn.commit()
    conn.close()

# Convertir en format lisible pour l'affichage
def format_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size/1024:.2f} KB"
    elif size < 1024**3:
        return f"{size/1024**2:.2f} MB"
    else:
        return f"{size/1024**3:.2f} GB"

# Initialiser la base de données au démarrage de l'application
init_db()

# Middleware pour vérifier si l'utilisateur est connecté
@app.before_request
def require_login():
    allowed_routes = ['login', 'static']
    if request.endpoint not in allowed_routes and 'user_id' not in session:
        return redirect(url_for('login'))

# Route pour la page de connexion
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (name,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            if user['is_admin']:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        
        flash('Incorrect username or password')
    
    return render_template('login.html', title='Login')

# Route pour la déconnexion
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Route pour user
@app.route('/user')
def user_dashboard():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    # Récupérer les informations de quota de l'utilisateur
    user_id = session.get('user_id')
    conn = get_db_connection()
    
    cursor = conn.execute('''
    SELECT storage_quota, max_folders, max_files, used_storage 
    FROM users 
    WHERE id = ?
    ''', (user_id,))
    
    user_info = cursor.fetchone()
    
    # Compter le nombre de dossiers et fichiers de l'utilisateur
    cursor = conn.execute('''
    SELECT COUNT(*) as folder_count 
    FROM folders 
    WHERE owner_id = ?
    ''', (user_id,))
    
    folder_count = cursor.fetchone()['folder_count']
    
    cursor = conn.execute('''
    SELECT COUNT(*) as file_count 
    FROM files 
    WHERE uploaded_by = ?
    ''', (user_id,))
    
    file_count = cursor.fetchone()['file_count']
    
    conn.close()
    
    # Calculer les pourcentages d'utilisation
    storage_percent = (user_info['used_storage'] / user_info['storage_quota']) * 100 if user_info['storage_quota'] > 0 else 0
    folder_percent = (folder_count / user_info['max_folders']) * 100 if user_info['max_folders'] > 0 else 0
    file_percent = (file_count / user_info['max_files']) * 100 if user_info['max_files'] > 0 else 0
    
    
    user_quota = {
        'storage_used': format_size(user_info['used_storage']),
        'storage_total': format_size(user_info['storage_quota']),
        'storage_percent': storage_percent,
        'folders_used': folder_count,
        'folders_total': user_info['max_folders'],
        'folders_percent': folder_percent,
        'files_used': file_count,
        'files_total': user_info['max_files'],
        'files_percent': file_percent
    }
   
    return render_template('user.html', user_quota=user_quota)

# Route pour l'admin
@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('user_dashboard'))
    
    return render_template('admin.html')

# Route pour l'administration des utilisateurs
@app.route('/administration', methods=['GET'])
def administration():
    if not session.get('is_admin'):
        return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    
    # Récupérer tous les utilisateurs sauf l'admin connecté
    cursor = conn.execute('''
    SELECT u.*, 
           (SELECT COUNT(*) FROM folders WHERE owner_id = u.id) as folder_count,
           (SELECT COUNT(*) FROM files WHERE uploaded_by = u.id) as file_count
    FROM users u
    WHERE u.id != ?
    ORDER BY u.username
    ''', (session.get('user_id'),))
    
    users = cursor.fetchall()
    
    
    users_list = []
    for user in users:
        users_list.append({
            'id': user['id'],
            'username': user['username'],
            'is_admin': user['is_admin'],
            'storage_quota': format_size(user['storage_quota']),
            'used_storage': format_size(user['used_storage']),
            'storage_percent': (user['used_storage'] / user['storage_quota']) * 100 if user['storage_quota'] > 0 else 0,
            'max_folders': user['max_folders'],
            'folder_count': user['folder_count'],
            'folder_percent': (user['folder_count'] / user['max_folders']) * 100 if user['max_folders'] > 0 else 0,
            'max_files': user['max_files'],
            'file_count': user['file_count'],
            'file_percent': (user['file_count'] / user['max_files']) * 100 if user['max_files'] > 0 else 0
        })

    conn.close()
    
    return render_template('administration1.html', users=users_list)

# Route pour ajouter un nouvel utilisateur
@app.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('is_admin'):
        return redirect(url_for('user_dashboard'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = 1 if request.form.get('is_admin') == 'on' else 0
    
    # Convertir les tailles en octets
    def parse_size(size_str):
        size_str = size_str.strip().upper()
        multipliers = {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3}
        
        if size_str.endswith(('KB', 'MB', 'GB')):
            for suffix, multiplier in multipliers.items():
                if size_str.endswith(suffix):
                    try:
                        return int(float(size_str[:-len(suffix)]) * multiplier)
                    except ValueError:
                        return 104857600  # 100 MB par défaut
        try:
            return int(size_str)
        except ValueError:
            return 104857600  # 100 MB par défaut
    
    storage_quota = parse_size(request.form.get('storage_quota', '100MB'))
    max_folders = int(request.form.get('max_folders', 10))
    max_files = int(request.form.get('max_files', 50))
    
    conn = get_db_connection()
    
    # Vérifier si l'utilisateur existe déjà
    cursor = conn.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        flash(f"The user {username} already exists. Please choose a different username.")
        conn.close()
        return redirect(url_for('administration'))
    
    # Créer le nouvel utilisateur
    password_hash = generate_password_hash(password)
    cursor = conn.execute('''
    INSERT INTO users (username, password, is_admin, storage_quota, max_folders, max_files)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, password_hash, is_admin, storage_quota, max_folders, max_files))
    
    user_id = cursor.lastrowid
    conn.commit()
    
    # Créer le dossier personnel de l'utilisateur
    create_personal_folder(user_id, username)
    
    flash(f"User {username} created successfully.")
    conn.close()
    
    return redirect(url_for('administration'))

# Route pour modifier un utilisateur existant
@app.route('/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    
    # Vérifier si l'utilisateur existe
    cursor = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash("User not found")
        conn.close()
        return redirect(url_for('administration'))
    
    # Mettre à jour les informations de l'utilisateur
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = 1 if request.form.get('is_admin') == 'on' else 0
    
    # Convertir les tailles en octets
    def parse_size(size_str):
        size_str = size_str.strip().upper()
        multipliers = {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3}
        
        if size_str.endswith(('KB', 'MB', 'GB')):
            for suffix, multiplier in multipliers.items():
                if size_str.endswith(suffix):
                    try:
                        return int(float(size_str[:-len(suffix)]) * multiplier)
                    except ValueError:
                        return 104857600  # 100 MB par défaut
        try:
            return int(size_str)
        except ValueError:
            return 104857600  # 100 MB par défaut
    
    storage_quota = parse_size(request.form.get('storage_quota', '100MB'))
    max_folders = int(request.form.get('max_folders', 10))
    max_files = int(request.form.get('max_files', 50))
    
    # Mettre à jour l'utilisateur
    if password:
        password_hash = generate_password_hash(password)
        conn.execute('''
        UPDATE users 
        SET username = ?, password = ?, is_admin = ?, storage_quota = ?, max_folders = ?, max_files = ?
        WHERE id = ?
        ''', (username, password_hash, is_admin, storage_quota, max_folders, max_files, user_id))
    else:
        conn.execute('''
        UPDATE users 
        SET username = ?, is_admin = ?, storage_quota = ?, max_folders = ?, max_files = ?
        WHERE id = ?
        ''', (username, is_admin, storage_quota, max_folders, max_files, user_id))
    
    conn.commit()
    
    flash(f"User {username} updated successfully.")
    conn.close()
    
    return redirect(url_for('administration'))

# Route pour supprimer un utilisateur
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    
    # Vérifier si l'utilisateur existe
    cursor = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash("User not found")
        conn.close()
        return redirect(url_for('administration'))
    
    # Récupérer les fichiers de l'utilisateur pour suppression physique
    cursor = conn.execute('SELECT filename FROM files WHERE uploaded_by = ?', (user_id,))
    files = cursor.fetchall()
    
    # Supprimer les fichiers physiques
    for file in files:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Erreur lors de la suppression du fichier: {e}")
    
    # Supprimer l'utilisateur et tous ses dossiers/fichiers (grâce aux contraintes ON DELETE CASCADE)
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    
    flash(f"User {user['username']} deleted successfully.")
    conn.close()
    
    return redirect(url_for('administration'))

# Route pour browser les fichiers
# Route pour télécharger un fichier
@app.route('/download/<int:file_id>')
def download_file(file_id):
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', 0)
    
    conn = get_db_connection()
    
    # Obtenir les informations sur le fichier
    cursor = conn.execute('''
        SELECT f.*, folder_id FROM files f
        WHERE f.id = ?
    ''', (file_id,))
    
    file = cursor.fetchone()
    
    if not file:
        flash("The requested file does not exist.")
        conn.close()
        return redirect(url_for('browse'))
    
    # Vérifier si l'utilisateur a accès au dossier contenant le fichier
    if not is_admin and not can_view(user_id, file['folder_id']):
        flash("You do not have access to this file.")
        conn.close()
        return redirect(url_for('browse'))
    
    conn.close()
    
    # Envoyer le fichier
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        file['filename'], 
        as_attachment=True,
        download_name=file['original_filename']
    )

# Route pour l'API de suppression (utilisée par les boutons AJAX)
@app.route('/api/delete', methods=['POST'])
def api_delete():
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', 0)
    
    if not request.is_json:
        return jsonify({"success": False, "message": "Invalid request format"}), 400
    
    data = request.get_json()
    item_type = data.get('type')
    item_id = data.get('id')
    
    if not item_type or not item_id:
        return jsonify({"success": False, "message": "Missing parameters"}), 400
    
    conn = get_db_connection()
    
    if item_type == 'folder':
        # Vérifier si l'utilisateur est le propriétaire du dossier ou admin
        cursor = conn.execute('SELECT owner_id FROM folders WHERE id = ?', (item_id,))
        folder = cursor.fetchone()
        
        if not folder:
            conn.close()
            return jsonify({"success": False, "message": "Folder not found"}), 404
        
        if not is_admin and folder['owner_id'] != user_id:
            conn.close()
            return jsonify({"success": False, "message": "You do not have permission to delete this folder"}), 403

        
        # 1) Récupérer la somme des fichiers
        cursor = conn.execute('SELECT SUM(filesize) as total FROM files WHERE folder_id = ?', (item_id,))
        result = cursor.fetchone()
        total_size = result['total'] if result['total'] else 0

        # 2) Mettre à jour le storage
        conn.execute('UPDATE users SET used_storage = used_storage - ? WHERE id = ?', (total_size, folder['owner_id']))


        # probleme de suppression de fichier dans les sous dossiers

        # Exécuter la requête récursive pour récupérer tous les fichiers dans le dossier et ses sous-dossiers
        conn.execute('''
        SELECT filename
        FROM files f
        WHERE f.folder_id IN (
            SELECT id
            FROM folders
            WHERE parent_folder_id = ?
            UNION
            SELECT id
            FROM folders
            WHERE id = ?
        )
        ''', (item_id, item_id))

        # Fetch all files
        files = conn.fetchall()

        # Loop through the files and delete them
        for file in files:
            try:
                # Build the file path
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
                
                # Check if the file exists and remove it
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"File {file['filename']} has been successfully deleted.")
            except Exception as e:
                print(f"Error while deleting the file {file['filename']}: {e}")



        # Supprimer le dossier et tout son contenu (les contraintes ON DELETE CASCADE s'occupent des dossiers enfants et fichiers)
        conn.execute('DELETE FROM folders WHERE id = ?', (item_id,))
        
    elif item_type == 'file':
        # Vérifier si l'utilisateur est l'uploader du fichier ou admin
        cursor = conn.execute('SELECT uploaded_by, filename, filesize FROM files WHERE id = ?', (item_id,))
        file = cursor.fetchone()
        
        if not file:
            conn.close()
            return jsonify({"success": False, "message": "File not found"}), 404
        
        if not is_admin and file['uploaded_by'] != user_id:
            conn.close()
            return jsonify({"success": False, "message": "You do not have permission to delete this file"}), 403
        
        # Supprimer le fichier de la base de données
        conn.execute('DELETE FROM files WHERE id = ?', (item_id,))
        
        # Mettre à jour le stockage utilisé
        conn.execute('''
        UPDATE users
        SET used_storage = used_storage - ?
        WHERE id = ?
        ''', (file['filesize'], file['uploaded_by']))
        
        # Supprimer le fichier physique
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error while deleting the file: {e}")
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

# Modification de la route browse pour gérer les suppressions et les quotas
@app.route('/browse/<int:folder_id>', methods=['GET', 'POST'])
@app.route('/browse', methods=['GET', 'POST'])
def browse(folder_id=None):
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', 0)
    
    conn = get_db_connection()
    
    # Si aucun folder_id n'est spécifié, afficher le dossier personnel de l'utilisateur
    if folder_id is None:
        cursor = conn.execute('''
            SELECT id FROM folders 
            WHERE owner_id = ? AND parent_folder_id IS NULL
        ''', (user_id,))
        personal_folder = cursor.fetchone()
        
        if personal_folder:
            folder_id = personal_folder['id']
        else:
            # Si l'utilisateur n'a pas de dossier personnel, en créer un
            create_personal_folder(user_id, session.get('username'))
            cursor = conn.execute('''
                SELECT id FROM folders 
                WHERE owner_id = ? AND parent_folder_id IS NULL
            ''', (user_id,))
            personal_folder = cursor.fetchone()
            folder_id = personal_folder['id']
    
    # Vérifier si l'utilisateur a accès au dossier demandé
    if not is_admin and not can_view(user_id, folder_id):
        flash("You do not have access to this folder.")
        conn.close()
        return redirect(url_for('browse'))
    
    # Obtenir les informations sur le dossier actuel
    cursor = conn.execute('''
        SELECT f.*, u.username as owner_name
        FROM folders f
        JOIN users u ON f.owner_id = u.id
        WHERE f.id = ?
    ''', (folder_id,))
    current_folder = cursor.fetchone()
    
    if not current_folder:
        flash("The requested folder does not exist.")
        conn.close()
        return redirect(url_for('browse'))
    
    # Traitement des actions POST
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'upload' and request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                # Vérifier le quota avant l'upload
                file_size = file.content_length if hasattr(file, 'content_length') else 0
                quota_ok, message = check_quota(user_id, file_size)
                
                if not quota_ok:
                    flash(message)
                    return redirect(url_for('browse', folder_id=folder_id))
                
                filename = secure_filename(file.filename)
                # Générer un nom de fichier unique pour le stockage
                unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                
                # Obtenir la taille réelle du fichier
                file_size = os.path.getsize(file_path)
                
                # Vérifier à nouveau le quota avec la taille réelle
                quota_ok, message = check_quota(user_id, file_size)
                
                # Probleme d'affishage de message flash
                if not quota_ok:
                    # Supprimer le fichier si le quota est dépassé
                    os.remove(file_path)
                    flash(message)
                    return redirect(url_for('browse', folder_id=folder_id))
                
                # Enregistrer le fichier dans la base de données
                conn.execute('''
                    INSERT INTO files (filename, original_filename, folder_id, uploaded_by, upload_date, filesize)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (unique_filename, filename, folder_id, user_id, datetime.now(), file_size))
                conn.commit()

                # Mettre à jour le stockage utilisé par l'utilisateur
                update_used_storage(user_id, file_size)
                
                
                
                flash(f'File {filename} uploaded successfully.')
                return redirect(url_for('browse', folder_id=folder_id))
            else:
                flash('Unauthorized file type')
        
        elif action == 'create_folder':
            folder_name = request.form.get('folder_name')
            if folder_name:
                # Vérifier si le quota de dossiers est atteint
                quota_ok, message = check_quota(user_id, new_folder=True)
                
                if not quota_ok:
                    flash(message)
                    return redirect(url_for('browse', folder_id=folder_id))
                
                conn.execute('''
                    INSERT INTO folders (folder_name, parent_folder_id, owner_id, is_public, created_date)
                    VALUES (?, ?, ?, 0, ?)
                ''', (folder_name, folder_id, user_id, datetime.now()))
                conn.commit()
                conn.close()
                
                flash(f'Folder {folder_name} created successfully')
                return redirect(url_for('browse', folder_id=folder_id))
        
        elif action == 'delete_folder':
            delete_folder_id = request.form.get('folder_id')
            
            # Vérifier si l'utilisateur est le propriétaire du dossier ou admin
            cursor = conn.execute('SELECT owner_id FROM folders WHERE id = ?', (delete_folder_id,))
            folder = cursor.fetchone()
            
            if folder and (is_admin or folder['owner_id'] == user_id):
                conn.execute('DELETE FROM folders WHERE id = ?', (delete_folder_id,))
                conn.commit()
                flash('Folder deleted successfully')
            else:
                flash("You do not have permission to delete this folder")
            
            return redirect(url_for('browse', folder_id=folder_id))
        
        elif action == 'delete_file':
            delete_file_id = request.form.get('file_id')
            
            # Vérifier si l'utilisateur est l'uploader du fichier ou admin
            cursor = conn.execute('SELECT uploaded_by, filename, filesize FROM files WHERE id = ?', (delete_file_id,))
            file = cursor.fetchone()
            
            if file and (is_admin or file['uploaded_by'] == user_id):
                # Mettre à jour le stockage utilisé
                conn.execute('''
                UPDATE users
                SET used_storage = used_storage - ?
                WHERE id = ?
                ''', (file['filesize'], file['uploaded_by']))
                
                conn.execute('DELETE FROM files WHERE id = ?', (delete_file_id,))
                conn.commit()
                
                # Supprimer le fichier physique
                try:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f"Erreur lors de la suppression du fichier: {e}")
                
                flash('File deleted successfully')
            else:
                flash("Vous n'avez pas les droits pour supprimer ce fichier")
            
            return redirect(url_for('browse', folder_id=folder_id))
    
    # Obtenir la hiérarchie complète des dossiers pour la navigation
    folder_hierarchy = []
    parent_id = current_folder['parent_folder_id']
    
    while parent_id is not None:
        cursor = conn.execute('SELECT id, folder_name, parent_folder_id FROM folders WHERE id = ?', (parent_id,))
        parent_folder = cursor.fetchone()
        if parent_folder:
            folder_hierarchy.insert(0, parent_folder)
            parent_id = parent_folder['parent_folder_id']
        else:
            break
    
    # Obtenir tous les sous-dossiers du dossier actuel
    cursor = conn.execute('''
        SELECT f.*, u.username as owner_name
        FROM folders f
        JOIN users u ON f.owner_id = u.id
        WHERE f.parent_folder_id = ?
        ORDER BY f.folder_name
    ''', (folder_id,))
    subfolders = cursor.fetchall()
    
    # Obtenir tous les fichiers du dossier actuel
    cursor = conn.execute('''
        SELECT f.*, u.username as uploaded_by_name
        FROM files f
        JOIN users u ON f.uploaded_by = u.id
        WHERE f.folder_id = ?
        ORDER BY f.original_filename
    ''', (folder_id,))
    files = cursor.fetchall()
    
    # Obtenir la structure complète des dossiers pour l'affichage en arborescence
    def get_folder_structure(root_folder_id):
        cursor = conn.execute('''
            SELECT id, folder_name FROM folders 
            WHERE parent_folder_id IS NULL AND (owner_id = ? OR is_public = 1 OR ? = 1)
            ORDER BY folder_name
        ''', (user_id, is_admin))
        
        root_folders = cursor.fetchall()
        folder_structure = []
        
        for folder in root_folders:
            folder_data = {
                'id': folder['id'],
                'name': folder['folder_name'],
                'is_current': folder['id'] == root_folder_id,
                'subfolders': get_subfolders(folder['id'], root_folder_id)
            }
            folder_structure.append(folder_data)
        
        return folder_structure
    
    def get_subfolders(parent_id, current_folder_id):
        cursor = conn.execute('''
            SELECT id, folder_name FROM folders 
            WHERE parent_folder_id = ? AND (owner_id = ? OR is_public = 1 OR ? = 1)
            ORDER BY folder_name
        ''', (parent_id, user_id, is_admin))
        
        folders = cursor.fetchall()
        subfolders_data = []
        
        for folder in folders:
            in_path = False
            temp_id = current_folder_id
            
            # Vérifier si ce dossier fait partie du chemin vers le dossier actuel
            while temp_id:
                cursor = conn.execute('SELECT parent_folder_id FROM folders WHERE id = ?', (temp_id,))
                parent = cursor.fetchone()
                if parent and parent['parent_folder_id'] == folder['id']:
                    in_path = True
                    break
                temp_id = parent['parent_folder_id'] if parent else None
            
            folder_data = {
                'id': folder['id'],
                'name': folder['folder_name'],
                'is_current': folder['id'] == current_folder_id,
                'expanded': folder['id'] == current_folder_id or in_path,
                'subfolders': get_subfolders(folder['id'], current_folder_id)
            }
            subfolders_data.append(folder_data)
        
        return subfolders_data
    
    # Obtenir la structure de dossiers pour l'arborescence
    folder_structure = get_folder_structure(folder_id)
    
    # Récupérer les informations de quota de l'utilisateur pour l'affichage
    if not is_admin:
        cursor = conn.execute('''
        SELECT storage_quota, max_folders, max_files, used_storage 
        FROM users 
        WHERE id = ?
        ''', (user_id,))
        
        user_info = cursor.fetchone()
        
        # Compter le nombre de dossiers et fichiers de l'utilisateur
        cursor = conn.execute('''
        SELECT COUNT(*) as folder_count 
        FROM folders 
        WHERE owner_id = ?
        ''', (user_id,))
        
        folder_count = cursor.fetchone()['folder_count']
        
        cursor = conn.execute('''
        SELECT COUNT(*) as file_count 
        FROM files 
        WHERE uploaded_by = ?
        ''', (user_id,))
        
        file_count = cursor.fetchone()['file_count']
        
        # Calculer les pourcentages d'utilisation
        storage_percent = (user_info['used_storage'] / user_info['storage_quota']) * 100 if user_info['storage_quota'] > 0 else 0
        folder_percent = (folder_count / user_info['max_folders']) * 100 if user_info['max_folders'] > 0 else 0
        file_percent = (file_count / user_info['max_files']) * 100 if user_info['max_files'] > 0 else 0
        
        # Convertir les tailles en format lisible
        def format_size(size):
            if size < 1024:
                return f"{size} B"
            elif size < 1024**2:
                return f"{size/1024:.2f} KB"
            elif size < 1024**3:
                return f"{size/1024**2:.2f} MB"
            else:
                return f"{size/1024**3:.2f} GB"
        
        user_quota = {
            'storage_used': format_size(user_info['used_storage']),
            'storage_total': format_size(user_info['storage_quota']),
            'storage_percent': storage_percent,
            'folders_used': folder_count,
            'folders_total': user_info['max_folders'],
            'folders_percent': folder_percent,
            'files_used': file_count,
            'files_total': user_info['max_files'],
            'files_percent': file_percent
        }
    else:
        user_quota = None
    
    conn.close()
    
    return render_template('browse.html', 
                          current_folder=current_folder,
                          folder_hierarchy=folder_hierarchy,
                          subfolders=subfolders,
                          files=files,
                          folder_structure=folder_structure,
                          is_admin=is_admin,
                          user_quota=user_quota)




# test
@app.route('/view_text/<int:file_id>')
def view_text_file(file_id):
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', 0)
    
    # Extensions autorisées pour l'affichage
    ALLOWED_TEXT_EXTENSIONS = {
        '.txt', '.py', '.html', '.css', '.js', 
        '.json', '.xml', '.csv', '.md', '.yaml', 
        '.yml', '.ini', '.cfg', '.sh', '.php',
    }
    
    conn = get_db_connection()
    
    # Obtenir les informations sur le fichier
    cursor = conn.execute('''
        SELECT f.*, folder_id FROM files f
        WHERE f.id = ?
    ''', (file_id,))
    
    file = cursor.fetchone()
    
    if not file:
        flash("The requested file does not exist.")
        conn.close()
        return redirect(url_for('browse'))
    
    # Vérifier si l'utilisateur a accès au dossier contenant le fichier
    if not is_admin and not can_view(user_id, file['folder_id']):
        flash("You do not have permission to view this file.")
        conn.close()
        return redirect(url_for('browse'))
    
    # Obtenir l'extension du fichier
    file_ext = os.path.splitext(file['original_filename'])[1].lower()
    
    # Vérifier si le fichier est un type de texte affichable
    if file_ext not in ALLOWED_TEXT_EXTENSIONS:
        flash("This file type cannot be displayed as text.")
        conn.close()
        return redirect(url_for('browse'))
    
    # Lire le contenu du fichier
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        except Exception as e:
            flash(f"Error reading file: {str(e)}")
            conn.close()
            return redirect(url_for('browse'))
    except Exception as e:
        flash(f"Error reading file: {str(e)}")
        conn.close()
        return redirect(url_for('browse'))
    
    conn.close()
    
    # Déterminer le mode de syntax highlighting (optionnel)
    syntax_modes = {
        '.py': 'python',
        '.html': 'html',
        '.css': 'css',
        '.js': 'javascript',
        '.json': 'json',
        '.xml': 'xml',
        '.md': 'markdown',
        '.yaml': 'yaml',
        '.yml': 'yaml'
    }

    # test
    syntax_mode = syntax_modes.get(file_ext, 'plaintext')
  
    return render_template('view_text_test.html', 
                         filename=file['original_filename'],
                         content=content,
                         file_id=file_id,
                         syntax_mode=syntax_mode)
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)