import os
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class ChaCha20Cipher:
    def __init__(self):
        # Automatically generate a ChaCha20-Poly1305 key on initialization
        self.key = ChaCha20Poly1305.generate_key()

    def encrypt(self, data: bytes) -> dict:
        """
        Encrypt `data` using ChaCha20-Poly1305.
        Returns a dict containing:
          - 'ciphertext': bytes
          - 'nonce': bytes
          - 'time': float (encryption time in seconds)
        """
        chacha = ChaCha20Poly1305(self.key)
        nonce = os.urandom(12)
        start = time.perf_counter()
        ciphertext = chacha.encrypt(nonce, data, None)
        end = time.perf_counter()

        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'time': end - start
        }

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> dict:
        """
        Decrypt `ciphertext` (bytes) using ChaCha20-Poly1305 with the stored key and provided nonce.
        Returns a dict containing:
          - 'plaintext': bytes
          - 'time': float (decryption time in seconds)
        """
        chacha = ChaCha20Poly1305(self.key)
        start = time.perf_counter()
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        end = time.perf_counter()

        return {
            'plaintext': plaintext,
            'time': end - start
        }

    def benchmark(self, data: bytes, iterations: int) -> dict:
        """
        Run `iterations` of encrypt/decrypt on `data` and collect timing information.
        Returns a dict:
          - 'enc_times': list[float]
          - 'dec_times': list[float]
          - 'cipher_size': int
        """
        enc_times = []
        dec_times = []
        last_ciphertext = b''
        last_nonce = b''

        for _ in range(iterations):
            result_enc = self.encrypt(data)
            enc_times.append(result_enc['time'])
            last_ciphertext = result_enc['ciphertext']
            last_nonce = result_enc['nonce']

            result_dec = self.decrypt(last_nonce, last_ciphertext)
            dec_times.append(result_dec['time'])

        return {
            'enc_times': enc_times,
            'dec_times': dec_times,
            'cipher_size': len(last_ciphertext)
        }
