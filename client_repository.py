from sqlalchemy import create_engine, Column, Integer, String, DateTime, asc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from utils import *
Base = declarative_base()
Session = sessionmaker()
MyKey = None

def initialize_database():
    # Create the engine for the database
    engine = create_engine('sqlite:///client_database.db')

    # Create all tables defined in the models
    Base.metadata.create_all(bind=engine)

    # Bind the session to the engine
    Session.configure(bind=engine)

    return Session()


def find_session_key(username):
    session = Session()
    session_key = session.query(SessionKeys).filter_by(username=username).first()
    session.close()
    if session_key:
        return decrypt_data(MyKey,session_key.session_key)
    else:
        return None

#session_key should be serialized 
def add_session_key(username, session_key, expire_time, public_key):
    session_key = encrypt_data(MyKey,session_key)
    session = Session()
    try:
        session_key = SessionKeys(username=username, session_key=session_key, expire_time=expire_time,
                                  public_key=public_key)
        session.add(session_key)
        session.commit()
        return True
    except Exception as e:
        print(e)
        session.rollback()
        return False
    finally:
        session.close()


def remove_session(username):
    session = Session()
    try:
        session_key = session.query(SessionKeys).filter_by(username=username).first()
        if session_key:
            session.delete(session_key)
            session.commit()
            return True
        else:
            return False
    except Exception as e:
        print(e)
        session.rollback()
        return False
    finally:
        session.close()


def find_messages_between_users(user1, user2):
    session = Session()
    messages = session.query(Chat).filter(
        ((Chat.sender == user1) & (Chat.receiver == user2)) |
        ((Chat.sender == user2) & (Chat.receiver == user1))
    ).order_by(asc(Chat.time), asc(Chat.sequence_number)).all()
    session.close()
    decrypted_messages = []
    for message in messages:
        decrypted_messages.append(decrypt_data(MyKey,messages))
    return decrypted_messages

def add_chat_message(sender, receiver, message, time, sequence_number):
    encrypted_message = encrypt_data(MyKey,message)
    session = Session()
    try:
        chat_message = Chat(sender=sender, receiver=receiver, message=encrypted_message, time=time, sequence_number=sequence_number)
        session.add(chat_message)
        session.commit()
        return True
    except Exception as e:
        print(f"Error adding chat message: {e}")
        session.rollback()
        return False
    finally:
        session.close()


class SessionKeys(Base):
    __tablename__ = 'session_keys'

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    session_key = Column(String(255), nullable=False)
    public_key = Column(String(4096))
    expire_time = Column(DateTime)


class Chat(Base):
    __tablename__ = 'chat'

    id = Column(Integer, primary_key=True)
    sender = Column(String, nullable=False)
    receiver = Column(String, nullable=False)
    message = Column(String, nullable=False)
    time = Column(DateTime, nullable=False)
    sequence_number = Column(Integer, nullable=False)
