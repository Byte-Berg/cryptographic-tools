# Cryptographic Tools

A Python-based graphical application for experimenting with and demonstrating cryptographic algorithms and concepts.

The project is based around a graphical user interface built with Tkinter and implements the cryptographic functionality using Python's standard library wherever possible.
## Features

The project provides tools for working with several cryptographic concepts, including:

* **Cryptographic hashing** using algorithms provided by Python's `hashlib` (SHA-3, SHA-256, and SHA-512 based operations).
* **Byte-array based cryptographic operations** including XOR operations, modular addition, and byte-array transformations.
* **ARX-style encryption and decryption** operations.
* **Block-cipher related functionality** including Counter-mode (CTR) and CBC-style encryption/decryption.
* **File encryption and decryption** utilities for securely processing entire files.
* **Key generation** using cryptographically secure randomness provided by `random.SystemRandom`.
* **Large-number modular arithmetic** and probabilistic primality testing using the Miller-Rabin algorithm.
* **Safe prime generation** driven by a customized Miller-Rabin implementation to find cryptographically secure primes.
* **Diffie-Hellman key exchange** functionality for secure parameter and shared secret generation.
* **Digital signature** generation and verification using a custom Schnorr-signature scheme.
* **A graphical user interface** built with Tkinter for seamless interaction with all cryptographic functionalities.

The repository also contains two handbooks that document parts of the project:
* `Handbook-01 signatures and setup.pdf` — information about signatures and initial setup.
* `Handbook-02 encryption and decryption.pdf` — information about encryption and decryption.


## Project Goal

The main goal of this project was to implement the cryptographic functionality without relying on external non-UI libraries.

In particular, the project aims to:
* **Avoid using non-UI third-party libraries** that are not included in the Python standard library. This means that the cryptographic functionality is implemented using Python's built-in capabilities and standard-library modules rather than depending on external cryptography packages.
* **The graphical interface uses Tkinter**, which is Python's standard GUI toolkit.

## Requirements

### Python
A working Python installation is required. The project uses Python standard-library modules including:
* `hashlib`
* `random`
* `datetime`
* `multiprocessing`
* `sys`
* `tkinter` (including `tkinter.ttk` and `tkinter.filedialog`)

The source code imports Tkinter directly for the graphical interface.

### Tkinter
Tkinter needs to be installed/enabled on your system. It is normally distributed with Python, but on some operating systems it may need to be installed separately.

You can check whether Tkinter is available by running:
```bash
python -m tkinter
```
If a small Tkinter test window appears, Tkinter is available.

On Linux distributions, Tkinter may be provided by a separate system package. For example, on Debian/Ubuntu-based systems:
```bash
sudo apt install python3-tk
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Byte-Berg/cryptographic-tools.git
   cd cryptographic-tools
   ```
2. Make sure Python and Tkinter are installed.
3. Run the application:
   ```bash
   python cryptographic-tools.py
   ```
   *(Depending on your system, you may need to use `python3 cryptographic-tools.py`)*

## Usage

Start the application with:
```bash
python cryptographic-tools.py
```
The application opens a graphical interface through which the available cryptographic operations can be accessed. The source code contains implementations for operations such as:
* Hashing
* XOR
* ARX-based processing
* Block operations
* Key generation
* Primality testing
* Encryption/decryption modes
* Digital signature creation and verification

## Cryptographic Components

### Hashing
The project uses Python's built-in `hashlib` module for cryptographic hashing. Examples used in the implementation include:
* SHA-3
* SHA-512
* SHA-256

For example, SHA-3 is used for checksum-related operations, while SHA-512 is used as part of the signature implementation.

### ARX Operations
The project contains an ARX-style cipher implementation based on:
* Addition
* Rotation/shift operations
* XOR

The implementation operates on byte arrays and performs modular addition, byte-array shifting, and XOR operations as part of its encryption/decryption process.

### Digital Signatures
The project includes functionality for:
* Generating private/public key pairs.
* Creating signatures for text and verifying them.
* Generating and checking safe primes.
* Performing modular exponentiation.

The signature implementation uses SHA-512 together with modular arithmetic and a generated random value.

### Primality Testing
A Miller-Rabin based probabilistic primality test is included for working with large prime numbers and safe primes.

## Project Structure

```text
cryptographic-tools/
│
├── cryptographic-tools.py
│
├── Handbook-01 signatures and setup.pdf
│
└── Handbook-02 encryption and decryption.pdf
```

* `cryptographic-tools.py`: The main Python application containing the graphical interface and cryptographic implementations.
* `Handbook-01 signatures and setup.pdf`: Documentation covering signatures and project setup.
* `Handbook-02 encryption and decryption.pdf`: Documentation covering encryption and decryption.

## Standard Library Only

One of the central design goals of this project is keeping the cryptographic implementation independent from external non-UI Python packages. The project therefore relies on functionality already provided by Python, including `hashlib`, `random`, `datetime`, `multiprocessing`, and `sys`. 

`tkinter` is used specifically for the graphical user interface. No external cryptographic Python package is required for the core implementation.

> [!IMPORTANT]
> This project is primarily intended for educational and experimental purposes. Implementing cryptographic algorithms yourself is useful for understanding how cryptography works, but a custom implementation should not automatically be considered suitable for protecting sensitive or production data. For real-world security-critical applications, established and professionally reviewed cryptographic libraries should generally be preferred.

## License

This project is licensed under:
**Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)**

You may use and share the project according to the terms of the license, provided that the applicable attribution and NoDerivatives requirements are respected.

See the official license text for the complete terms:
https://creativecommons.org/licenses/by-nd/4.0/
