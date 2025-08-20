from app import app, db, User, DetectionHistory

def view_database():
    with app.app_context():
        print("=== Database Content Viewer ===")
        
        # View user table
        print("\n📋 User Table:")
        users = User.query.all()
        if users:
            for user in users:
                print(f"ID: {user.id}")
                print(f"Username: {user.username}")
                print(f"Email: {user.email}")
                print(f"Created At: {user.created_at}")
                print(f"Last Login: {user.last_login}")
                print("-" * 30)
        else:
            print("No user data")
        
        # View detection history table
        print("\n📊 Detection History Table:")
        detections = DetectionHistory.query.all()
        if detections:
            for detection in detections:
                print(f"ID: {detection.id}")
                print(f"User ID: {detection.user_id}")
                print(f"URL: {detection.url}")
                print(f"Safe Status: {'Safe' if detection.is_safe else 'Dangerous'}")
                print(f"Confidence: {detection.confidence_score:.2%}")
                print(f"Detected At: {detection.detected_at}")
                print("-" * 30)
        else:
            print("No detection history data")
        
        # Statistics
        print("\n📈 Statistics:")
        print(f"Total Users: {User.query.count()}")
        print(f"Total Detections: {DetectionHistory.query.count()}")
        print(f"Safe Websites: {DetectionHistory.query.filter_by(is_safe=True).count()}")
        print(f"Dangerous Websites: {DetectionHistory.query.filter_by(is_safe=False).count()}")

if __name__ == "__main__":
    view_database() 