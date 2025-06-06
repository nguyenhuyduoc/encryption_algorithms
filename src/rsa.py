import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


class RSACipher:
    def __init__(self, key_size: int = 2048):
        """
        key_size: RSA key length in bits (default 2048).
        OAEP overhead = 2*hash_len + 2 = 2*32 + 2 = 66 bytes for SHA-256.
        Therefore, max_chunk_size = (key_size // 8) - 66.
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self.max_chunk_size = (key_size // 8) - 2 * hashes.SHA256().digest_size - 2

    def generate_keypair(self):
        """
        Generate an RSA keypair (public_key_object, private_key_object).
        Stores them in self.public_key & self.private_key.
        Returns (public_key_object, private_key_object).
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        return self.public_key, self.private_key

    def encrypt(self, data: bytes, public_key) -> dict:
        """
        Encrypt `data` (bytes) using RSA-OAEP:
          - Split data into chunks of size <= self.max_chunk_size.
          - For each chunk, perform public_key.encrypt(chunk, OAEP-SHA256).
        Returns a dict:
          - 'ciphertext': list[bytes]   (list of encrypted chunks)
          - 'time': float (total encryption time in seconds)
        """
        if public_key is None:
            raise ValueError("Public key is not set. Call generate_keypair() first.")

        ciphertext_chunks = []
        start = time.perf_counter()
        for i in range(0, len(data), self.max_chunk_size):
            chunk = data[i:i + self.max_chunk_size]
            ct = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            ciphertext_chunks.append(ct)
        end = time.perf_counter()

        return {
            'ciphertext': ciphertext_chunks,
            'time': end - start
        }

    def decrypt(self, ciphertext_chunks: list, private_key) -> dict:
        """
        Decrypt a list of RSA-OAEP-encrypted chunks using private_key:
          - For each chunk, call private_key.decrypt(chunk, OAEP-SHA256).
          - Concatenate decrypted chunks into a single plaintext bytes.
        Returns a dict:
          - 'plaintext': bytes
          - 'time': float (total decryption time in seconds)
        """
        if private_key is None:
            raise ValueError("Private key is not set. Call generate_keypair() first.")

        plaintext = b''
        start = time.perf_counter()
        for ct in ciphertext_chunks:
            pt_chunk = private_key.decrypt(
                ct,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            plaintext += pt_chunk
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
          - 'cipher_size': int (total bytes in ciphertext across all chunks for the last iteration)
        """
        if self.public_key is None or self.private_key is None:
            raise ValueError("Keypair not initialized. Call generate_keypair() first.")

        enc_times = []
        dec_times = []
        last_cipher_chunks = []

        for _ in range(iterations):
            result_enc = self.encrypt(data, self.public_key)
            enc_times.append(result_enc['time'])
            last_cipher_chunks = result_enc['ciphertext']

            result_dec = self.decrypt(last_cipher_chunks, self.private_key)
            dec_times.append(result_dec['time'])

        # Calculate total size of the ciphertext bytes
        total_cipher_bytes = sum(len(chunk) for chunk in last_cipher_chunks)

        return {
            'enc_times': enc_times,
            'dec_times': dec_times,
            'cipher_size': total_cipher_bytes
        }
