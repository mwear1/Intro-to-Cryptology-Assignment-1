# Assignment 1: Repeating-Key XOR

**Name:** Matthew Wear  
**Course:** Intro to Cryptology  
**Language:** C++17  
**Compiler:** g++ 14.1.0 (MSYS2 UCRT64)  
**Platform:** Windows

## Description

This program implements a byte-oriented repeating-key XOR cipher. It supports key generation, encryption, and decryption from the command line.

The program provides the following commands:

```text
xor_vigenere keygen --length <positive integer>
xor_vigenere encrypt --key <hex> --text <UTF-8 string>
xor_vigenere decrypt --key <hex> --ciphertext <hex>
```

## Build Instructions

This project was developed and tested on Windows using MSYS2 UCRT64 with g++ 14.1.0.

Build the main program with:

```powershell
g++ -std=c++17 -g -static-libgcc -static-libstdc++ main.cpp xor_vigenere.cpp -lbcrypt -o xor_vigenere.exe
```

## Run Instructions

After building the program, use the following commands from the project directory.

### Generate a Key

```powershell
.\xor_vigenere.exe keygen --length 16
```
Example output:
```
4d19472903f5910eb751550825f27500
```

### Encrypt Text
The key and ciphertext are provided as hexadecimal strings. Plaintext input and decrypted output are handled as UTF-8 text.

Basic Example:
```powershell
.\xor_vigenere.exe encrypt --key 6b6579 --text hello
```
Example output:
```
030015070a
```
Example with spaces:
```powershell
.\xor_vigenere.exe encrypt --key 494345 --text "Attack at dawn!"
```
Example output:
```
08373128202e6922316927243e2d64
```

## Testing

The project includes both C++ unit-style tests and PowerShell command-line tests to validate both code and inputs.

### C++ Tests
These tests cover the repeating-key XOR core, known-answer vectors, round-trip encryption/decryption, empty data, repeating keys, keys longer than messages, arbitrary byte values, UTF-8 validation, hexadecimal conversion, and key generation.
Run:

```powershell
.\tests.exe
```
Expected output:
```
All tests passed.
```

### Command-Line Tests
The command-line tests verify valid encryption/decryption, invalid input rejection, key-length validation, key-generation format, UTF-8 handling, and nonzero exit codes for expected input errors.
```powershell
.\cli_tests.ps1
```
Expected output:
```
Passed: 14
Failed: 0
All CLI tests passed.
```

## Assumptions and Limitations

- This implementation is intended for Windows and uses the Windows `BCryptGenRandom` API for secure key generation.
- The program uses Windows console UTF-8 handling so multibyte plaintext and decrypted text display correctly.
- Keys and ciphertexts must be provided as hexadecimal strings.
- Plaintext passed to `encrypt` is converted to UTF-8 before encryption.
- The program includes handling for Windows PowerShell dropping explicitly empty command-line arguments such as `""`.
- Repeating-key XOR is intentionally insecure and should only be used for educational purposes.

## Assistance Disclosure

Stack Overflow, Cppreference, and Claude were used as development resources for this assignment.

Stack Overflow and Cppreference were consulted for guidance on C++/Windows implementation and debugging issues.

Claude assisted with debugging the Windows/MSYS2 build environment, identifying UTF-8 handling issues, and suggesting test cases.

I reviewed and implemented the code myself and verified the results by compiling and running the program, comparing output against the provided known-answer test vectors, running the C++ automated tests, and running the PowerShell command-line test suite.