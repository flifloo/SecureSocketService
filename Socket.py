import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


class Socket:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key = None
        self.fernet = None

    def send(self, sock: socket.socket, message: str):
        if type(message) != bytes:
            message = message.encode("Utf8")
        if self.fernet:
            message = self.fernet.encrypt(message)
        try:
            sock.send(message)
        except socket.error:
            raise ConnectionError("Fail to send")
        else:
            return True

    def receive(self, sock: socket.socket, utf8=True, fernet=True):
        try:
            response = sock.recv(1028)
        except socket.error:
            raise ConnectionError("Fail to receive")
        else:
            if self.fernet and fernet:
                response = self.fernet.decrypt(response)
            if utf8:
                response = response.decode("Utf8")
            return response

    def set_secure_connexion(self, sock: socket.socket):
        if not self.key:
            self.key = Fernet.generate_key()
            self.fernet = Fernet(self.key)

        public_key = serialization.load_pem_public_key(
            self.receive(sock, False, False),
            backend=default_backend()
        )

        sock.send(
            public_key.encrypt(
                self.key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        )

        if self.receive(sock) == "Key receive":
            self.send(sock, "Key valid")
            return True
        else:
            raise ConnectionError("Invalid key !")

    def get_secure_connexion(self, sock: socket.socket):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.send(sock, pem)

        self.key = private_key.decrypt(
            self.receive(sock, False, False),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        self.fernet = Fernet(self.key)

        self.send(sock, "Key receive")
        if self.receive(sock) != "Key valid":
            raise ConnectionError("Invalid key !")
        return True

    def connect_server(self, sock: socket.socket, host: str, port: int, service_id: int):
        try:
            sock.connect((host, port))
        except socket.error:
            raise ConnectionError("Can't connect to server !")
        else:
            self.get_secure_connexion(self.socket)
            self.send(sock, f"Client service ID: {service_id}")
            if self.receive(sock) != f"Server service ID: {service_id}":
                raise ConnectionError("Server service ID")
            return True

    def connect_client(self, sock: socket, service_id: int):
        connexion, address = sock.accept()
        self.set_secure_connexion(connexion)
        if self.receive(connexion) == f"Client service ID: {service_id}":
            self.send(connexion, f"Server service ID: {service_id}")
            return connexion
        else:
            raise ConnectionError("Invalid client service ID !")
