from sqlalchemy import create_engine, Column, Integer, String, DateTime, asc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

from utils import *

Base = declarative_base()
Session = sessionmaker()



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
        data = decrypt_data_simple(MyKey, session_key.session_key)
        return data
    else:
        return None


# session_key should be serialized
def add_session_key(username, session_key, expire_time, public_key):
    session_key = encrypt_data(MyKey, session_key)
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


# This method could throw exception
def find_messages_between_users(user1, user2, myKey, myUser):
    session = Session()
    query = session.query(Chat).filter(

        ((Chat.sender == user1) & (Chat.receiver == user2) & (Chat.username == myUser)) |
        ((Chat.sender == user2) & (Chat.receiver == user1) & (Chat.username == myUser))
    )
    messages = query.all()
    
    session.close()
    chat_part1 = []
    chat_part1_index = []
    i = 0
    for msg in messages:
        if(msg.sender == user1):
            chat_part1.append(msg)
            chat_part1_index.append(i)
        i+=1
    
    chat_part2 = []
    chat_part2_index = []
    i = 0
    for msg in messages:
        if(msg.sender == user2):
            chat_part2.append(msg)
            chat_part2_index.append(i)
        i+=1
    sorted_part1 = sorted(chat_part1, key=lambda chat: chat.sequence_number)    
    sorted_part2 = sorted(chat_part2, key=lambda chat: chat.sequence_number)
    messages = [None] * (len(sorted_part1) + len(sorted_part2))

    for i in range (len(sorted_part1)):
        messages[chat_part1_index[i]] = sorted_part1[i]
    
    for i in range (len(sorted_part2)):
        messages[chat_part2_index[i]] = sorted_part2[i]

    decrypted_messages = []
    for msg in messages:
        msg_string = decrypt_data_simple(myKey,msg.message)
        msg.message = msg_string
        decrypted_messages.append(msg)

    chat_strings = [str(chat) for chat in decrypted_messages]
    
    # decrypted_messages = []
    # for message in messages:
    #     decrypted_message = decrypt_data(MyKey, message)
    #     decrypted_messages.append(decrypted_message)
    return chat_strings

# Assuming you have already defined the 'Chat' class and its mapping to the database

def get_last_sequence_number(sender, receiver):
    try:
        session = Session()

        # Query the last sequence number
        last_sequence_number = session.query(func.coalesce(func.max(Chat.sequence_number), 0)).filter(
            Chat.sender == sender,
            Chat.receiver == receiver
        ).scalar()

        # Close the session and return the last sequence number
        session.close()
        return last_sequence_number

    except Exception as e:
        print(f"An error occurred: {e}")
        session.rollback()
        return None

def add_chat_message(sender, receiver, message, sequence_number, myKey, username):
    encrypted_message = encrypt_data(myKey, message)
    session = Session()
    try:
        chat_message = Chat(sender=sender, receiver=receiver, message=encrypted_message,
                            sequence_number=sequence_number, username =username)
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
    first_user = Column(String(255), unique=True, nullable=False)
    second_user = Column(String(255), unique=True, nullable=False)
    session_key = Column(String(255), nullable=False)
    public_key = Column(String(4096))
    expire_time = Column(DateTime)


class Chat(Base):
    def __repr__(self):
        return f"{self.sender} -> {self.receiver}: {self.message}"
    __tablename__ = 'chat'

    id = Column(Integer, primary_key=True)
    sender = Column(String, nullable=False)
    receiver = Column(String, nullable=False)
    message = Column(String, nullable=False)
    username = Column(String, nullable=False)
    sequence_number = Column(Integer, nullable=False)
