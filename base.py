import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
from cryptography import fernet


class Node:
    def __init__(self,
                 name: str,
                 parent_key: bytes,
                 children: list["Node"] = None,
                 content: str = None,
                 password: str = None):

        self.name = name

        if not children:
            self.children = []
        else:
            self.children = children

        key = self.get_key(parent_key)

        f = fernet.Fernet(key)
        if content:
            self.content = f.encrypt(bytes(content, "utf-8"))
        else:
            self.content = f.encrypt(b"no content")
        self.enc_key = None
        self.enc_pass = None
        if password:
            self.set_password(parent_key=parent_key, password=password)


    def get_key(self, parent_key=None, password=None):
        if parent_key:
            key_hash = hashlib.sha256(parent_key, usedforsecurity=True)
            key_hash = key_hash.digest()

            salt = hashlib.sha256(bytes(self.name, "utf-8"), usedforsecurity=True)
            salt = salt.digest()

            return key_from_hash(key_hash, salt)
        elif password:
            key = self.get_key(parent_key=bytes(password, "utf-8"))

            f = fernet.Fernet(key)

            return f.decrypt(self.enc_key)

        else:
            raise Exception("neither parent_key nor password was provided")

    def get_content(self, key):
        if self.content == None:
            return "No content"
        f = fernet.Fernet(key)
        return f.decrypt(self.content).decode("utf-8")

    def set_password(self, password, parent_key=None, old_pass=None):
        if parent_key:
            key = self.get_key(parent_key=parent_key)
        elif old_pass:
            key = self.get_key(password=bytes(old_pass, "utf-8"))
        else:
            raise Exception("Can't set password old_pass or parent_key needs to be provided")

        try:
            self.get_content(key)
        except fernet.InvalidToken:
            raise Exception("Wrong parent_key or password can't set password")

        password_key = self.get_key(parent_key=bytes(password, "utf-8"))

        f = fernet.Fernet(password_key)
        self.enc_key = f.encrypt(key)
        f = fernet.Fernet(key)
        self.enc_pass = f.encrypt(bytes(password, "utf-8"))

    def update_content(self, key, content: str):
        f = fernet.Fernet(key)
        try:
            f.decrypt(self.content)
        except fernet.InvalidToken:
            raise Exception("Wrong parent_key or password")

        self.content = f.encrypt(bytes(content, "utf-8"))

    def add_child(self, child_to_add: "Node"):
        name = child_to_add.name
        for child in self.children:
            if child.name == name:
                raise Exception("Child with that name already exists")
        self.children.append(child_to_add)


    def get_child_node(self, path: list[str]):
        if len(path) == 0:
            return self
        for child in self.children:
            if child.name == path[0]:
                return child.get_child_node(path[1:])
        print(f"didn't find {path}")

    def get_child_key(self, key, path: list[str]):
        if len(path) == 0:
            return key
        for child in self.children:
            if child.name == path[0]:
                child_key = child.get_key(parent_key=key)
                return child.get_child_key(child_key, path[1:])
        print("didn't find shit")

    def rename(self, name, password=None, parent_key=None, new_parent_key=None):
        if password:
            key = self.get_key(password=password)
        elif parent_key:
            key = self.get_key(parent_key=parent_key)
        else:
            raise Exception("No auth provided")

        if self.name == "root_node":
            self.content = None
        content = self.get_content(key)

        if new_parent_key:
            if not password:
                new = Node(name, new_parent_key, content=content, password=self.get_pass(parent_key))
            else:
                new = Node(name, new_parent_key, content=content, password=password)
        else:
            if not password:
                new = Node(name, parent_key, content=content, password=self.get_pass(parent_key))
            else:
                new = Node(name, parent_key, content=content, password=password)


        if not new_parent_key:
            new_parent_key = parent_key

        self.enc_key = new.enc_key
        self.content = new.content
        self.name = name
        for child in self.children:
            child.rename(child.name, parent_key=key, new_parent_key=self.get_key(new_parent_key))

    def get_pass(self, parent_key):
        if not self.enc_pass:
            return None
        key = self.get_key(parent_key=parent_key)
        f = fernet.Fernet(key)
        return f.decrypt(self.enc_pass).decode("utf-8")





def key_from_hash(password_hash: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password_hash))

