from app import app, db, User
import os
from werkzeug.security import generate_password_hash

def init_db():
    # Supprimer la base de données existante
    if os.path.exists('cloud.db'):
        os.remove('cloud.db')
    
    # Créer une nouvelle base de données
    with app.app_context():
        db.create_all()
        
        # Créer le compte administrateur
        admin = User(
            email='admin@example.com',
            is_admin=True,
            storage_limit=1024 * 1024 * 1024  # 1 GB
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        
        print("Base de données réinitialisée avec succès!")
        print("Compte administrateur créé :")
        print("Email : admin@example.com")
        print("Mot de passe : admin123")

if __name__ == '__main__':
    init_db() 