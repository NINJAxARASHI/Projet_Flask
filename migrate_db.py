from app import app, db
from sqlalchemy import text

def migrate():
    with app.app_context():
        try:
            # Vérifier les colonnes existantes
            result = db.session.execute(text("PRAGMA table_info(file)"))
            existing_columns = [row[1] for row in result]
            
            # Ajouter les colonnes manquantes
            if 'hmac_signature' not in existing_columns:
                db.session.execute(text("""
                    ALTER TABLE file ADD COLUMN hmac_signature TEXT;
                """))
                print("Colonne hmac_signature ajoutée")
            
            if 'file_public_key' not in existing_columns:
                db.session.execute(text("""
                    ALTER TABLE file ADD COLUMN file_public_key TEXT;
                """))
                print("Colonne file_public_key ajoutée")
            
            db.session.commit()
            print("Migration terminée avec succès")
            
        except Exception as e:
            db.session.rollback()
            print(f"Erreur lors de la migration : {str(e)}")

if __name__ == '__main__':
    migrate() 