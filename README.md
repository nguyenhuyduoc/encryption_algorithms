
# Encryption Algorithms Benchmark Suite

This project, **encryption-algorithms**, provides implementations and benchmarks of five encryption algorithms:
- **AES** (Advanced Encryption Standard)
- **RSA** (Rivest–Shamir–Adleman)
- **ECC** (Elliptic Curve Cryptography)
- **ChaCha20-Poly1305**
- **Kyber** (Post-quantum Key Encapsulation)

It includes source code for each algorithm, a benchmarking script, and instructions to compare encryption/decryption performance on an input file.

## Project Structure

```
encryption-algorithms/
├── requirements.txt
├── README.md
├── src/
│   ├── aes.py
│   ├── rsa.py
│   ├── ecc.py
│   ├── chacha20.py
│   └── kyber.py
├── data/
│   └── input.txt
├── results/
│   └── report.txt
└── benchmark.py
```

- **requirements.txt**: Python dependencies required by the project.
- **README.md**: Instructions and overview of the project.
- **src/**: Contains implementation modules for each encryption algorithm and the benchmarking script.
  - `aes.py`: AES encryption/decryption functions (ECB, CBC, OFB, CTR, or AES-GCM as used).
  - `rsa.py`: RSA encryption/decryption functions using OAEP padding.
  - `ecc.py`: ECC encryption/decryption functions.
  - `chacha20.py`: ChaCha20-Poly1305 encryption/decryption functions.
  - `kyber.py`: Kyber KEM encryption/decryption functions.
  - `benchmark.py`: Entry point script that runs all five algorithms on a given input file, measures encryption/decryption time (in microseconds), records cipher sizes, and generates a comparative report.
- **data/**: Contains the plaintext file(s) to encrypt. By default, `input.txt`.
- **results/**: Stores the benchmark output. After running `benchmark.py`, `report.txt` will be created or updated here.
- **tests/**: (Optional) Contains unit tests for each algorithm module.

## Prerequisites

- Python **3.8+** installed.
- Install required packages with:

```bash
pip install -r requirements.txt
```

This installs:
- `cryptography`
- `oqs`
- `numpy`
- `matplotlib` (used for plotting, if needed in extensions)
# Manual Installation Guide

If automatic installation fails, you can install packages manually:

```bash
pip install cryptography
pip install oqs
pip install numpy
pip install matplotlib
```

Alternatively, use your system's package manager:

- **Debian/Ubuntu:**
  ```bash
  sudo apt-get update
  sudo apt-get install python3-pip python3-numpy python3-matplotlib
  pip install cryptography oqs
  ```


## Installing liboqs from Source

To get the latest **liboqs** C library (and Python bindings) directly from GitHub:

```bash
# 1. Clone the repository
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# 2. Build and install the core library
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install

# 3. (Optional) Update linker cache
sudo ldconfig

# 4. Install Python bindings
cd ../python
pip install .

# 5. Verify installation
python -c "import oqs; print(oqs.get_enabled_KEMs())"
```
## Usage

1. **Prepare Input**
   - Place your plaintext in `data/input.txt`. You can modify or replace this file as needed.

2. **Run Benchmark**
   - Navigate to the project root directory.
   - Execute the benchmark script:

     ```bash
     python src/benchmark.py
     ```

   - The script will:
     - Load `data/input.txt`.
     - For each algorithm (AES, RSA, ECC, ChaCha20, Kyber):
       - Encrypt the file.
       - Decrypt the resulting ciphertext.
       - Measure average encryption and decryption times (in microseconds).
       - Record the size of the ciphertext.
       - Perform a configurable number of iterations (adjustable in `benchmark.py`).
     - Save the summary results into `results/report.txt`.

3. **View Results**
   - Open `results/report.txt` to see a table of:
     - Algorithm name
     - Average encryption time (μs)
     - Average decryption time (μs)
     - Ciphertext size (bytes)
     - Number of iterations used

4. **Adjust Benchmark Parameters**
   - In `src/benchmark.py`, you can modify:
     - `ITERATIONS`: Number of iterations for each algorithm (default values vary per algorithm to balance runtime).
     - Time measurement units (already set to microseconds).
     - Warm-up iterations (if applicable).

## File Descriptions

- **aes.py**  
  Implements AES-GCM encryption and decryption functions. 
- **rsa.py**  
  Implements RSA-OAEP encryption and decryption.  
- **ecc.py**  
  Implements ECC encryption and decryption.  
- **chacha20.py**  
  Implements ChaCha20-Poly1305 encryption and decryption.  
- **kyber.py**  
  Implements Kyber KEM key generation, encapsulation, and decapsulation.
- **benchmark.py**  
  Main script that runs all algorithms, measures performance, and generates `results/report.txt`.

## Output: `results/report.txt`


## Extending the Project

- **Unit Tests**: Add tests in the `tests/` directory to verify correctness of each algorithm.
- **Visualization**: Use `matplotlib` to plot performance comparisons.
- **Additional Algorithms**: Integrate more algorithms by adding new modules under `src/` and updating `benchmark.py`.

## Contributing

1. Fork this repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request describing your changes.


