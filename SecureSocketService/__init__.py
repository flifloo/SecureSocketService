import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


class Socket:
    """Self
    Socket service with security system"""
    def __init__(self):
        """Self
        Socket service with security system"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Set the socket object
        self.service_id = 0
        self.key = None  # Set the key encryption
        self.fernet = None  # Set the encryption object

    def send(self, sock: socket.socket, message: str, encryption=True):
        """self, sock (socket), message (str), encryption (bool)
        Send a message with a specific socket, encrypted if available"""
        if type(message) != bytes:  # If the message are not a bytes type, encode in Utf8
            message = message.encode("Utf8")
        if self.fernet and encryption:  # Encrypt if available
            message = self.fernet.encrypt(message)
        try:  # Try to send, if fail raise a custom error
            sock.send(message)
        except socket.error:
            raise ConnectionError("Fail to send")
        else:
            return True

    def receive(self, sock: socket.socket, utf8=True, encryption=True):
        """self, sock (socket), utf8 (bool), encryption (bool)
        Receive a message from a socket"""
        try:  # Try to receive, else raise a custom error
            response = sock.recv(1028)
        except socket.error:
            raise ConnectionError("Fail to receive")
        else:
            if self.fernet and encryption:  # Encrypt if available
                response = self.fernet.decrypt(response)
            if utf8:  # decode the utf8 by default
                response = response.decode("Utf8")
            return response

    def set_secure_connexion(self, sock: socket.socket):
        """self, sock (socket)
        Set encryption for a connected socket"""
        if not self.key:  # If any key generated, generate one
            self.key = Fernet.generate_key()
            self.fernet = Fernet(self.key)

        # Receive the public key of the targed socket
        public_key = serialization.load_pem_public_key(
            self.receive(sock, False, False),
            backend=default_backend()
        )

        # Encrypt the key and send back with private key encryption to the target socket
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

        if self.receive(sock) == "Key receive":  # Check if the kay is valid
            self.send(sock, "Key valid")
            return True
        else:
            raise ConnectionError("Invalid key !")

    def get_secure_connexion(self, sock: socket.socket):
        """self, sock (socket)
        Get encryption for a connected socket"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()  # Create pubic kay

        # Make a sendable public key
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.send(sock, pem)  # Send the public key

        # Decrypt the receive key with the private key and set it
        self.key = private_key.decrypt(
            self.receive(sock, False, False),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        self.fernet = Fernet(self.key)  # Set the encryption object

        self.send(sock, "Key receive")  # Check if the key is valid
        if self.receive(sock) != "Key valid":
            raise ConnectionError("Invalid key !")
        return True

    def connect_server(self, host: str, port: int, encryption=True):
        """self, sock (socket), host (str), port (int), service_id (int), encryption (bool)
        Connect to a socket server"""
        try:  # Try to connect, else raise a custom error
            self.socket.connect((host, port))
        except socket.error:
            raise ConnectionError("Can't connect to server !")
        else:
            if encryption:  # Set secure connexion is asked
                self.get_secure_connexion(self.socket)

            self.send(self.socket, f"Client service ID: {self.service_id}")  # Check if service id match
            if self.receive(self.socket) != f"Server service ID: {self.service_id}":
                raise ConnectionError("Server service ID")
            return True

    def connect_client(self, encryption=True):
        """self, sock (socket), service_id (int), encryption (bool)
        Connect a socket client to the server"""
        connexion, address = self.socket.accept()  # Await for connexion
        if encryption:
            self.set_secure_connexion(connexion)

        if self.receive(connexion) == f"Client service ID: {self.service_id}":  # Check if service id match
            self.send(connexion, f"Server service ID: {self.service_id}")
            return connexion, address
        else:
            raise ConnectionError("Invalid client service ID !")
