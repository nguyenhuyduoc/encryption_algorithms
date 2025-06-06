#!/usr/bin/env python3

import os
import sys
import argparse
import time

import numpy as np
import matplotlib.pyplot as plt

# Add src/ to sys.path so we can import our cipher modules
base_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(base_dir, 'src')
sys.path.append(src_dir)

from aes import AESCipher
from chacha20 import ChaCha20Cipher
from rsa import RSACipher
from ecc import ECCCipher
from kyber import KyberCipher


def seconds_to_microseconds(seconds: float) -> float:
    """
    Convert seconds to microseconds.
    """
    return seconds * 1_000_000


def parse_args():
    parser = argparse.ArgumentParser(
        description="Benchmark encryption/decryption speed of AES, ChaCha20, RSA, ECC, and Kyber")
    parser.add_argument(
        "--input-file",
        type=str,
        default="data/input.txt",
        help="Path to the input file to encrypt (raw bytes). (default: data/input.txt)")
    parser.add_argument(
        "--output-dir",
        type=str,
        default="results",
        help="Directory to store the results (report.txt, benchmark.png). (default: results)")
    parser.add_argument(
        "--iters",
        type=int,
        default=100,
        help="Number of iterations for benchmarking (default: 100)")
    parser.add_argument(
        "--kyber-algo",
        type=str,
        default="Kyber512",
        help="Which Kyber KEM algorithm to use (e.g., Kyber512, Kyber768, Kyber1024). (default: Kyber512)")
    return parser.parse_args()


def load_input_data(path: str) -> bytes:
    """
    Read the entire contents of `path` as bytes. Exit if the file does not exist.
    """
    if not os.path.isfile(path):
        print(f"Error: Input file does not exist: {path}")
        sys.exit(1)
    with open(path, "rb") as f:
        return f.read()


def generate_report(final_results: dict, input_file_path: str, output_dir: str):
    """
    Create `output_dir` if needed.
    Write `report.txt` containing:
      - A table with average encryption/decryption times (μs), ciphertext sizes (bytes), and #iterations
      - An "Insights" section at the end that comments on how encryption time scales with file size.
    Also generate a bar chart (log-scale) comparing encryption vs. decryption times.
    """
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "report.txt")

    # Get the size of the input file for reference
    input_file_size = os.path.getsize(input_file_path)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("Encryption/Decryption Benchmark Results\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Input file: {input_file_path}\n")
        f.write(f"Input file size: {input_file_size} bytes\n\n")
        f.write(f"{'Algorithm':<15} {'Avg Enc (μs)':>15} {'Avg Dec (μs)':>15} {'Cipher Size (bytes)':>20} {'Iterations':>12}\n")
        f.write("-" * 85 + "\n")

        # Write each algorithm’s row
        for algo, res in final_results.items():
            if "error" in res:
                f.write(f"{algo:<15} {'ERROR':>15} {'ERROR':>15} {'-':>20} {res['iters']:>12}\n")
            else:
                enc_mean_us = seconds_to_microseconds(np.mean(res["enc_times"]))
                dec_mean_us = seconds_to_microseconds(np.mean(res["dec_times"]))
                cipher_size = res["cipher_size"]
                iters = res["iters"]
                f.write(f"{algo:<15} {enc_mean_us:15.2f} {dec_mean_us:15.2f} {cipher_size:20d} {iters:12d}\n")

        # Add a short “Insights” section
        f.write("\nInsights:\n")
        f.write("-" * 60 + "\n")
        f.write(f"The input file size was {input_file_size} bytes. Notice how symmetric algorithms (AES-GCM, ChaCha20) ")
        f.write("tend to have very low encryption/decryption times relative to asymmetric and post-quantum schemes.\n")
        f.write("RSA-OAEP takes significantly longer due to expensive modular exponentiation and chunking. ")
        f.write("ECC (ECDH+AES) is faster than RSA but still slower than pure symmetric ciphers because of the ECDH key agreement step. ")
        f.write("Kyber (post-quantum KEM + AES) typically falls between ECC and RSA in encryption time, but its ciphertext size is larger than that of AES or ECC-GCM alone.\n")
        f.write("Overall, for large files, symmetric algorithms are preferred, whereas asymmetric or KEM-based algorithms are primarily used for encrypting small symmetric keys under a hybrid encryption scheme.\n")

    # --- Generate bar chart with log-scale on Y-axis ---
    algos = []
    enc_means_us = []
    dec_means_us = []
    for algo, res in final_results.items():
        if "error" in res:
            continue
        algos.append(algo)
        enc_means_us.append(seconds_to_microseconds(np.mean(res["enc_times"])))
        dec_means_us.append(seconds_to_microseconds(np.mean(res["dec_times"])))

    x = np.arange(len(algos))
    width = 0.35

    plt.figure(figsize=(10, 6))
    plt.yscale('log')
    plt.bar(x - width/2, enc_means_us, width, label="Enc (μs)")
    plt.bar(x + width/2, dec_means_us, width, label="Dec (μs)")
    plt.xticks(x, algos, rotation=20)
    plt.ylabel("Time (μs) [log scale]")
    plt.title("Average Encryption/Decryption Times (Log-scale)")
    plt.legend()
    plt.grid(which='both', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "benchmark.png"))
    plt.close()
    # --- End of chart generation ---


def main():
    args = parse_args()

    # Read the input file as raw bytes
    input_data = load_input_data(args.input_file)
    iters_common = args.iters
    kyber_algo = args.kyber_algo

    final_results = {}

    # 1. AES-GCM
    try:
        aes = AESCipher()
        res = aes.benchmark(input_data, iters_common)
        final_results["AES-GCM"] = {
            "enc_times": res["enc_times"],
            "dec_times": res["dec_times"],
            "cipher_size": res["cipher_size"],
            "iters": iters_common
        }
        print("Benchmark AES complete.")
    except Exception as e:
        final_results["AES-GCM"] = {"error": str(e), "iters": iters_common}

    # 2. ChaCha20-Poly1305
    try:
        chacha = ChaCha20Cipher()
        res = chacha.benchmark(input_data, iters_common)
        final_results["ChaCha20"] = {
            "enc_times": res["enc_times"],
            "dec_times": res["dec_times"],
            "cipher_size": res["cipher_size"],
            "iters": iters_common
        }
        print("Benchmark Chacha20 complete.")
    except Exception as e:
        final_results["ChaCha20"] = {"error": str(e), "iters": iters_common}

    # 3. RSA-OAEP
    try:
        rsa_cipher = RSACipher()
        rsa_cipher.generate_keypair()
        res = rsa_cipher.benchmark(input_data, iters_common)
        final_results["RSA-OAEP"] = {
            "enc_times": res["enc_times"],
            "dec_times": res["dec_times"],
            "cipher_size": res["cipher_size"],
            "iters": iters_common
        }
        print("Benchmark RSA complete.")
    except Exception as e:
        final_results["RSA-OAEP"] = {"error": str(e), "iters": iters_common}

    # 4. ECC (ECDH + AES-GCM)
    try:
        ecc_cipher = ECCCipher()
        ecc_cipher.generate_keypair()
        res = ecc_cipher.benchmark(input_data, iters_common)
        final_results["ECC"] = {
            "enc_times": res["enc_times"],
            "dec_times": res["dec_times"],
            "cipher_size": res["cipher_size"],
            "iters": iters_common
        }
        print("Benchmark ECC complete.")
    except Exception as e:
        final_results["ECC"] = {"error": str(e), "iters": iters_common}

    # 5. Kyber (KEM + AES-GCM)
    try:
        kyber_cipher = KyberCipher(kyber_algo)
        res = kyber_cipher.benchmark(input_data, iters_common)
        final_results[f"Kyber-{kyber_algo}"] = {
            "enc_times": res["enc_times"],
            "dec_times": res["dec_times"],
            "cipher_size": res["cipher_size"],
            "iters": iters_common
        }
        print("Benchmark Kyber complete.")
    except Exception as e:
        final_results[f"Kyber-{kyber_algo}"] = {"error": str(e), "iters": iters_common}

    # Generate the final report (including ciphertext sizes and insights)
    generate_report(final_results, args.input_file, args.output_dir)
    print(f"Results and report saved in: {args.output_dir}")


if __name__ == "__main__":
    main()
