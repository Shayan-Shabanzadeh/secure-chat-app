from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.exc import SQLAlchemyError, NoResultFound
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()
Session = sessionmaker()


def initialize_database():
    # Create the engine for the database
    engine = create_engine('sqlite:///server_database.db')

    # Create all tables defined in the models
    Base.metadata.create_all(bind=engine)

    # Bind the session to the engine
    Session.configure(bind=engine)

    return Session()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, unique=True, nullable=False)
    public_key = Column(String, nullable=False)
    is_online = Column(Boolean, nullable=False)
    master_key = Column(String)

def add_user(username, password, public_key, is_online):
    session = Session()
    try:
        user = User(username=username, password=password, public_key=public_key, is_online=is_online)
        session.add(user)
        session.commit()
        print("User added successfully!")
    except SQLAlchemyError as e:
        session.rollback()
        print("Error occurred while adding user to the database.")
        print("Error:", str(e))
        raise e
    finally:
        session.close()


def change_user_status(username, is_online):
    session = Session()
    try:
        user = session.query(User).filter_by(username=username).first()
        if user:
            user.is_online = is_online
            session.commit()
            print("User status updated successfully!")
        else:
            print("User not found.")
    except SQLAlchemyError as e:
        session.rollback()
        print("Error occurred while changing user status.")
        print("Error:", str(e))
    finally:
        session.close()


def find_all_online_users():
    session = Session()
    online_users = session.query(User.username).filter_by(is_online=True).all()
    session.close()
    return [user.username for user in online_users]


def find_user_by_username(username):
    session = Session()
    try:
        user = session.query(User).filter_by(username=username).one()
        return user
    except NoResultFound:
        return None
    finally:
        session.close()


def set_master_key(username, master_key):
    session = Session()
    try:
        user = session.query(User).filter_by(username=username).first()
        if user:
            user.master_key = master_key
            session.commit()
            print("Master key set successfully!")
        else:
            print("User not found.")
    except SQLAlchemyError as e:
        session.rollback()
        print("Error occurred while setting master key.")
        print("Error:", str(e))
    finally:
        session.close()


# Define the User entity

