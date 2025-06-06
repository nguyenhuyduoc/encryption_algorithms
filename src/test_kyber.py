from kyber import KyberCipher  # Nếu bạn để kyber.py trong cùng thư mục với test_kyber.py
# Hoặc: from src.kyber import KyberCipher  nếu bạn để test ở cấp cao hơn.

# Khởi tạo Kyber512
cipher = KyberCipher("Kyber512")

# Tạo keypair
public_key, secret_key = cipher.generate_keypair()

# Chuẩn bị message
message = b"Hello, Kyber!"

# Mã hóa
enc_res = cipher.encrypt(message, public_key)
print("Đã mã hóa xong.")

# Giải mã
dec_res = cipher.decrypt(
    kem_ciphertext=enc_res["kem_ciphertext"],
    nonce=enc_res["nonce"],
    ciphertext=enc_res["ciphertext"],
    secret_key=secret_key
)

print("Plaintext recovered:", dec_res["plaintext"])
print("Enc time (μs):", enc_res["time"] * 1_000_000)
print("Dec time (μs):", dec_res["time"] * 1_000_000)
