import os
import time

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Ensure KeyEncapsulation class is available in oqs
if hasattr(oqs, "KeyEncapsulation"):
    _oqs_kem_cls = oqs.KeyEncapsulation
else:
    available = ", ".join(dir(oqs))
    raise ImportError(
        "KeyEncapsulation class not found in module 'oqs'.\n"
        f"Available attributes in 'oqs': {available}"
    )


class KyberCipher:
    def __init__(self, kem_algorithm: str = "Kyber512"):
        """
        kem_algorithm: name of the Kyber KEM (e.g., "Kyber512", "Kyber768", "Kyber1024").
        Verifies that it is supported by oqs.get_supported_kem_mechanisms().
        """
        supported = oqs.get_supported_kem_mechanisms()
        if kem_algorithm not in supported:
            raise ValueError(
                f"KEM not supported: {kem_algorithm}. Supported mechanisms: {supported}"
            )

        # Initialize the KEM object; secret key is generated internally
        self.kem = _oqs_kem_cls(kem_algorithm)

    def generate_keypair(self):
        """
        Generate a keypair:
          - Calls generate_keypair() on the KEM object to get public_key (bytes).
          - Export the secret key from the KEM object.
        Returns (public_key: bytes, secret_key: bytes).
        """
        public_key = self.kem.generate_keypair()

        try:
            secret_key = self.kem.export_secret_key()
        except AttributeError:
            # Some bindings may use a different method name
            try:
                secret_key = self.kem.exportSecretKey()
            except Exception as e:
                raise RuntimeError(f"Unable to export secret_key: {e}")

        return public_key, secret_key

    def encrypt(self, data: bytes, public_key: bytes) -> dict:
        """
        Hybrid encryption: Kyber-KEM + AES-GCM
          1. Encapsulate to get (kem_ciphertext, shared_secret).
          2. Use shared_secret as AES-GCM key.
          3. Encrypt `data` with AES-GCM.
        Returns a dict:
          - 'kem_ciphertext': bytes
          - 'nonce': bytes
          - 'ciphertext': bytes
          - 'time': float (total time for KEM encapsulation + AES encryption, in seconds)
        """
        start = time.perf_counter()

        # Perform encapsulation (encap_secret() or encap())
        if hasattr(self.kem, "encap_secret"):
            encap_result = self.kem.encap_secret(public_key)
        else:
            encap_result = self.kem.encap(public_key)

        if isinstance(encap_result, (tuple, list)) and len(encap_result) >= 2:
            kem_ciphertext, shared_secret = encap_result[:2]
        elif isinstance(encap_result, dict):
            kem_ciphertext = encap_result.get("ciphertext") or encap_result.get("kem_ciphertext")
            shared_secret = encap_result.get("shared_secret") or encap_result.get("ss")
        else:
            raise ValueError(f"Unable to unpack (ciphertext, shared_secret) from encap(): {encap_result}")

        aes_key = shared_secret
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        end = time.perf_counter()
        return {
            "kem_ciphertext": kem_ciphertext,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "time": end - start
        }

    def decrypt(self, kem_ciphertext: bytes, nonce: bytes, ciphertext: bytes, secret_key: bytes) -> dict:
        """
        Hybrid decryption: Kyber-KEM + AES-GCM
          1. Decapsulate using kem_ciphertext to obtain shared_secret.
          2. Use shared_secret as the key for AES-GCM.
          3. Decrypt ciphertext with AES-GCM.
        Returns a dict:
          - 'plaintext': bytes
          - 'time': float (total time for KEM decapsulation + AES decryption, in seconds)
        """
        start = time.perf_counter()

        if hasattr(self.kem, "decap_secret"):
            shared_secret = self.kem.decap_secret(kem_ciphertext)
        else:
            shared_secret = self.kem.decap(kem_ciphertext)

        aes_key = shared_secret
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        end = time.perf_counter()
        return {
            "plaintext": plaintext,
            "time": end - start
        }

    def close(self):
        """
        Release the KEM object (garbage collector will clean up).
        """
        self.kem = None

    def benchmark(self, data: bytes, iterations: int) -> dict:
        """
        Run `iterations` of hybrid Kyber encrypt/decrypt on `data`. 
        Must call generate_keypair() once before calling this.
        Returns a dict:
          - 'enc_times': list[float]
          - 'dec_times': list[float]
          - 'cipher_size': int (size in bytes of the AES-GCM ciphertext in the last iteration; does not include KEM ciphertext length)
        """
        public_key, secret_key = self.generate_keypair()

        enc_times = []
        dec_times = []
        last_ciphertext = b''
        last_nonce = b''
        last_kem_ct = b''

        for _ in range(iterations):
            result_enc = self.encrypt(data, public_key)
            enc_times.append(result_enc['time'])
            last_ciphertext = result_enc['ciphertext']
            last_nonce = result_enc['nonce']
            last_kem_ct = result_enc['kem_ciphertext']

            result_dec = self.decrypt(last_kem_ct, last_nonce, last_ciphertext, secret_key)
            dec_times.append(result_dec['time'])

        return {
            'enc_times': enc_times,
            'dec_times': dec_times,
            'cipher_size': len(last_ciphertext)
        }
