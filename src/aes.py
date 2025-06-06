import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESCipher:
    def __init__(self):
        # Automatically generate a random 256-bit AES key on initialization
        self.key = AESGCM.generate_key(bit_length=256)

    def encrypt(self, data: bytes) -> dict:
        """
        Encrypt `data` using AES-GCM (256-bit).
        Returns a dict containing:
          - 'ciphertext': bytes
          - 'nonce': bytes
          - 'time': float (encryption time in seconds)
        """
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        start = time.perf_counter()
        ciphertext = aesgcm.encrypt(nonce, data, None)
        end = time.perf_counter()

        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'time': end - start
        }

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> dict:
        """
        Decrypt `ciphertext` (bytes) using AES-GCM with the stored key and provided nonce.
        Returns a dict containing:
          - 'plaintext': bytes
          - 'time': float (decryption time in seconds)
        """
        aesgcm = AESGCM(self.key)
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
        Returns a dict:
          - 'enc_times': list[float] (encryption times in seconds for each iteration)
          - 'dec_times': list[float] (decryption times in seconds for each iteration)
          - 'cipher_size': int (size in bytes of the ciphertext from the last iteration)
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
