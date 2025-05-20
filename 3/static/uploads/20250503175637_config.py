import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'clé-secrète-par-défaut'
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip'}
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'file_sharing.db')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 Mo - limite de taille pour le téléchargement
