"""Type stubs for the opaque-snake Rust extension module."""

from typing import Optional

# Exceptions
class OpaqueError(Exception):
    """Base exception for OPAQUE protocol errors."""
    ...

class ProtocolError(OpaqueError):
    """Error in the protocol flow (invalid state, wrong order)."""
    ...

class AuthenticationError(OpaqueError):
    """Authentication failed (wrong password or tampered message)."""
    ...

class SerializationError(OpaqueError):
    """Failed to serialize or deserialize a message or file."""
    ...

# Message types
class RegistrationRequest:
    """Client's initial registration message."""
    def to_bytes(self) -> bytes:
        """Serialize for network transmission."""
        ...

    @staticmethod
    def from_bytes(data: bytes) -> "RegistrationRequest":
        """Deserialize from network transmission."""
        ...

class RegistrationResponse:
    """Server's registration response message."""
    def to_bytes(self) -> bytes:
        """Serialize for network transmission."""
        ...

    @staticmethod
    def from_bytes(data: bytes) -> "RegistrationResponse":
        """Deserialize from network transmission."""
        ...

class RegistrationUpload:
    """Client's final registration message."""
    def to_bytes(self) -> bytes:
        """Serialize for network transmission."""
        ...

    @staticmethod
    def from_bytes(data: bytes) -> "RegistrationUpload":
        """Deserialize from network transmission."""
        ...

class CredentialRequest:
    """Client's initial login message."""
    def to_bytes(self) -> bytes:
        """Serialize for network transmission."""
        ...

    @staticmethod
    def from_bytes(data: bytes) -> "CredentialRequest":
        """Deserialize from network transmission."""
        ...

class CredentialResponse:
    """Server's login response message."""
    def to_bytes(self) -> bytes:
        """Serialize for network transmission."""
        ...

    @staticmethod
    def from_bytes(data: bytes) -> "CredentialResponse":
        """Deserialize from network transmission."""
        ...

class CredentialFinalization:
    """Client's final login message."""
    def to_bytes(self) -> bytes:
        """Serialize for network transmission."""
        ...

    @staticmethod
    def from_bytes(data: bytes) -> "CredentialFinalization":
        """Deserialize from network transmission."""
        ...

# Stored types
class PasswordFile:
    """Stored credential for a registered user.

    This must be stored securely on the server. It contains no
    information that would allow recovering the user's password.
    """
    def to_bytes(self) -> bytes:
        """Serialize for storage."""
        ...

    @staticmethod
    def from_bytes(data: bytes) -> "PasswordFile":
        """Deserialize from storage."""
        ...

# Result types
class SessionKeys:
    """Keys derived from a successful authentication."""
    @property
    def session_key(self) -> bytes:
        """64-byte shared session key."""
        ...

    @property
    def export_key(self) -> Optional[bytes]:
        """64-byte export key (may not be available on server side)."""
        ...

class RegistrationResult:
    """Result of completing client registration."""
    @property
    def upload(self) -> RegistrationUpload:
        """Message to send to server to complete registration."""
        ...

    @property
    def export_key(self) -> bytes:
        """Export key that can be used for additional key derivation."""
        ...

    @property
    def server_s_pk(self) -> bytes:
        """Server's static public key."""
        ...

class LoginResult:
    """Result of completing client login."""
    @property
    def finalization(self) -> CredentialFinalization:
        """Message to send to server to complete login."""
        ...

    @property
    def session_keys(self) -> SessionKeys:
        """Derived session keys."""
        ...

# State types (opaque, single-use)
class ClientRegistrationState:
    """Opaque state for client registration.

    This state can only be used once. Do not serialize.
    """
    ...

class ClientLoginState:
    """Opaque state for client login.

    This state can only be used once. Do not serialize.
    """
    ...

class ServerLoginState:
    """Opaque state for server login.

    This state can only be used once. Do not serialize.
    """
    ...

# Core classes
class OpaqueServer:
    """Server-side OPAQUE protocol handler.

    The server maintains a ServerSetup that should be persisted across
    restarts. User password files are stored separately.
    """
    def __init__(self, setup_bytes: Optional[bytes] = None) -> None:
        """Create a new server or restore from serialized setup.

        Args:
            setup_bytes: Previously serialized server setup, or None to create new.
        """
        ...

    def export_setup(self) -> bytes:
        """Serialize the server setup for persistent storage.

        This contains the server's private key and must be kept secret.
        """
        ...

    def create_registration_response(
        self,
        request: RegistrationRequest,
        user_id: str,
    ) -> RegistrationResponse:
        """Process a client registration request.

        Args:
            request: The client's registration request message.
            user_id: Unique identifier for this user (e.g., username or email).

        Returns:
            Response to send back to the client.
        """
        ...

    def finish_registration(self, upload: RegistrationUpload) -> PasswordFile:
        """Complete registration and create a password file.

        Args:
            upload: The client's registration upload message.

        Returns:
            Password file to store for this user.
        """
        ...

    def create_credential_response(
        self,
        request: CredentialRequest,
        user_id: str,
        password_file: PasswordFile,
    ) -> tuple[CredentialResponse, ServerLoginState]:
        """Process a client login request.

        Args:
            request: The client's credential request message.
            user_id: The user's identifier (must match registration).
            password_file: The stored password file for this user.

        Returns:
            Tuple of (response to send to client, server state for finish_login).
        """
        ...

    def finish_login(
        self,
        finalization: CredentialFinalization,
        state: ServerLoginState,
    ) -> SessionKeys:
        """Complete the login and derive session keys.

        Args:
            finalization: The client's credential finalization message.
            state: The server state from create_credential_response.

        Returns:
            Session keys shared with the client.

        Raises:
            AuthenticationError: If authentication fails.
            ProtocolError: If state has already been used.
        """
        ...

class OpaqueClient:
    """Client-side OPAQUE protocol handler.

    Clients do not need persistent state between sessions.
    """
    def __init__(self) -> None:
        """Create a new client."""
        ...

    def start_registration(
        self,
        password: str,
    ) -> tuple[RegistrationRequest, ClientRegistrationState]:
        """Begin the registration process.

        Args:
            password: The user's password.

        Returns:
            Tuple of (request to send to server, client state for finish).
        """
        ...

    def finish_registration(
        self,
        response: RegistrationResponse,
        state: ClientRegistrationState,
        password: str,
    ) -> RegistrationResult:
        """Complete registration with the server's response.

        Args:
            response: The server's registration response.
            state: The client state from start_registration.
            password: The same password used in start_registration.

        Returns:
            Registration result containing the upload message and export key.

        Raises:
            ProtocolError: If state has already been used.
        """
        ...

    def start_login(
        self,
        password: str,
    ) -> tuple[CredentialRequest, ClientLoginState]:
        """Begin the login process.

        Args:
            password: The user's password.

        Returns:
            Tuple of (request to send to server, client state for finish).
        """
        ...

    def finish_login(
        self,
        response: CredentialResponse,
        state: ClientLoginState,
        password: str,
    ) -> LoginResult:
        """Complete login with the server's response.

        Args:
            response: The server's credential response.
            state: The client state from start_login.
            password: The same password used in start_login.

        Returns:
            Login result containing session keys and finalization message.

        Raises:
            AuthenticationError: If authentication fails (wrong password).
            ProtocolError: If state has already been used.
        """
        ...
