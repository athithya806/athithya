from app import db, User
from werkzeug.security import generate_password_hash

def create_user(username, password, role):
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    user = User(username=username, password=hashed_password, role=role)
    db.session.add(user)
    db.session.commit()
    print(f"User {username} created with role {role}")

if __name__ == "__main__":
    # Create an admin user
    create_user('admin', 'admin_password', 'admin')

    # Create a regular user
    create_user('user', 'user_password', 'user')
