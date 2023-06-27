users = {}


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.is_login = False

    def login(self):
        self.is_login = True

    def logout(self):
        self.is_login = False


def find_user_with_username(username) -> User | None:
    for user in users:
        if user.username == username:
            return user
        return None


def add_user(user):
    users[user.username] = user


def create_new_user(username, password):
    new_user = User(username=username, password=password)
    add_user(new_user)
    return new_user
