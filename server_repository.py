from sqlalchemy import create_engine, Column, Integer, String, Boolean, Table, ForeignKey
from sqlalchemy.exc import SQLAlchemyError, NoResultFound
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

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


group_user_association = Table(
    'group_user_association',
    Base.metadata,
    Column('group_id', Integer, ForeignKey('groups.id')),
    Column('user_id', Integer, ForeignKey('users.id'))
)


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, unique=True, nullable=False)
    public_key = Column(String, nullable=False)
    is_online = Column(Boolean, nullable=False)
    master_key = Column(String)


class Group(Base):
    __tablename__ = 'groups'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    session_key = Column(String(255), nullable=False)

    # Define the many-to-many relationship with User
    users = relationship('User', secondary=group_user_association, back_populates='groups')


def create_group(group_name, session_key, admin_username, user_usernames):
    session = Session()
    try:
        # Retrieve the admin user by username
        admin = session.query(User).filter_by(username=admin_username).first()

        # Retrieve the user objects for the given usernames
        users = session.query(User).filter(User.username.in_(user_usernames)).all()

        group = Group(name=group_name, session_key=session_key, admin=admin)
        group.users.extend(users)

        session.add(group)
        session.commit()
        print("Group created successfully!")
    except Exception as e:
        session.rollback()
        print("Error occurred while creating a group.")
        print("Error:", str(e))
        raise e
    finally:
        session.close()



def update_group_session_key(group_id, new_session_key):
    session = Session()
    try:
        group = session.query(Group).get(group_id)
        if group:
            group.session_key = new_session_key
            session.commit()
            print("Group session key updated successfully!")
        else:
            print("Group not found.")
    except Exception as e:
        session.rollback()
        print("Error occurred while updating group session key.")
        print("Error:", str(e))
    finally:
        session.close()


def get_user_groups(username):
    session = Session()
    try:
        user = session.query(User).filter_by(username=username).first()
        if user:
            groups = user.groups
            group_names = [group.name for group in groups]
            return group_names
        else:
            print("User not found.")
            return []
    except Exception as e:
        print("Error occurred while retrieving user groups.")
        print("Error:", str(e))
        return []
    finally:
        session.close()


def add_user_to_group(username, group_id):
    session = Session()
    try:
        user = session.query(User).filter_by(username=username).first()
        group = session.query(Group).filter_by(id=group_id).first()
        if user and group:
            group.users.append(user)
            session.commit()
            print("User added to the group successfully!")
            return True
        else:
            print("User or group not found.")
            return False
    except Exception as e:
        session.rollback()
        print("Error occurred while adding user to the group.")
        print("Error:", str(e))
        return False
    finally:
        session.close()


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
