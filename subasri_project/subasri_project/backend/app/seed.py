"""Creates the default admin user if it doesn't already exist.

Run:  python -m app.seed
"""
from app.database import Base, engine, SessionLocal
from app.models import User, Role
from app.security import hash_password

DEFAULT_ADMIN_EMAIL = "admin@nids-platform.io"
DEFAULT_ADMIN_PASSWORD = "ChangeMe123!"


def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == DEFAULT_ADMIN_EMAIL).first()
        if existing:
            print(f"Admin user already exists: {DEFAULT_ADMIN_EMAIL}")
            return
        admin = User(
            name="Administrator",
            email=DEFAULT_ADMIN_EMAIL,
            hashed_password=hash_password(DEFAULT_ADMIN_PASSWORD),
            role=Role.admin,
        )
        db.add(admin)
        db.commit()
        print(f"Created admin user: {DEFAULT_ADMIN_EMAIL} / {DEFAULT_ADMIN_PASSWORD}")
        print("Log in and change this password immediately in a real deployment.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
