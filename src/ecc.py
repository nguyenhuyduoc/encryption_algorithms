import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ECCCipher:
    def __init__(self, curve: ec.EllipticCurve = ec.SECP256R1()):
        """
        curve: Elliptic curve (default SECP256R1).
        Uses ECIES-like encryption under the hood.
        """
        self.curve = curve
        self.private_key = None
        self.public_key = None
        self._last_ephemeral_public = None  # Will hold ephemeral public key for decryption

    def generate_keypair(self):
        """
        Generate an ECC keypair (public_key_pem, private_key_object).
        Stores keys in self.private_key & self.public_key.
        Returns (public_key_pem: bytes, private_key_object).
        """
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()

        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem, self.private_key

    def encrypt(self, data: bytes, peer_public_key_pem: bytes) -> dict:
        """
        Encrypt `data` using an ECIES-like process:
          1. Load peer's public key from PEM.
          2. Generate ephemeral keypair.
          3. Derive shared_secret via ECDH.
          4. Derive AES key via HKDF(shared_secret).
          5. Encrypt `data` with AES-GCM using that key.
        Returns a dict:
          - 'nonce': bytes
          - 'ciphertext': bytes
          - 'time': float (encryption time in seconds)
        """
        # Load peer's public key
        peer_public = serialization.load_pem_public_key(peer_public_key_pem)

        # Generate ephemeral keypair
        ephemeral_private = ec.generate_private_key(self.curve)
        ephemeral_public = ephemeral_private.public_key()
        ephemeral_public_pem = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Store ephemeral public key for later decryption
        self._last_ephemeral_public = ephemeral_public_pem

        # Derive shared_secret via ECDH
        shared_secret = ephemeral_private.exchange(ec.ECDH(), peer_public)

        # Derive AES key (32 bytes) via HKDF( SHA-256 )
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ECCEncryption'
        )
        aes_key = hkdf.derive(shared_secret)

        # Encrypt with AES-GCM
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        start = time.perf_counter()
        ciphertext = aesgcm.encrypt(nonce, data, None)
        end = time.perf_counter()

        return {
            'nonce': nonce,
            'ciphertext': ciphertext,
            'time': end - start
        }

    def decrypt(self, nonce: bytes, ciphertext: bytes, private_key) -> dict:
        """
        Decrypt `ciphertext` using the provided `private_key` and the stored ephemeral public key:
          1. Load ephemeral public key from self._last_ephemeral_public.
          2. Derive shared_secret via ECDH between private_key and ephemeral public.
          3. Derive AES key via HKDF(shared_secret).
          4. Decrypt with AES-GCM.
        Returns a dict:
          - 'plaintext': bytes
          - 'time': float (decryption time in seconds)
        """
        if self._last_ephemeral_public is None:
            raise ValueError("No ephemeral public key stored. Call encrypt() before decrypt().")

        ephemeral_pub = serialization.load_pem_public_key(self._last_ephemeral_public)

        # Derive shared_secret via ECDH
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_pub)

        # Derive AES key via HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ECCEncryption'
        )
        aes_key = hkdf.derive(shared_secret)

        aesgcm = AESGCM(aes_key)
        start = time.perf_counter()
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        end = time.perf_counter()

        return {
            'plaintext': plaintext,
            'time': end - start
        }

    def benchmark(self, data: bytes, iterations: int) -> dict:
        """
        Run `iterations` of encrypt/decrypt on `data` and collect timing information.
        Must call generate_keypair() once before calling this.
        Returns a dict:
          - 'enc_times': list[float]
          - 'dec_times': list[float]
          - 'cipher_size': int
        """
        if self.public_key is None or self.private_key is None:
            raise ValueError("Keypair not initialized. Call generate_keypair() first.")

        enc_times = []
        dec_times = []
        last_ciphertext = b''
        last_nonce = b''

        for _ in range(iterations):
            result_enc = self.encrypt(data, self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
            enc_times.append(result_enc['time'])
            last_ciphertext = result_enc['ciphertext']
            last_nonce = result_enc['nonce']

            result_dec = self.decrypt(last_nonce, last_ciphertext, self.private_key)
            dec_times.append(result_dec['time'])

        return {
            'enc_times': enc_times,
            'dec_times': dec_times,
            'cipher_size': len(last_ciphertext)
        }
