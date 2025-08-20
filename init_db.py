from app import app, db, User
from datetime import datetime

def init_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database tables created")
        
        # Check if users already exist
        if User.query.first() is None:
            # Create default admin user
            admin_user = User(
                username='admin',
                email='admin@example.com',
                created_at=datetime.utcnow()
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created:")
            print("Username: admin")
            print("Password: admin123")
        else:
            print("Users already exist in database, skipping default user creation")

if __name__ == "__main__":
    init_database() 