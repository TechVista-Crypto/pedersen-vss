# Pedersen Verifiable Secret Sharing (VSS) Implementation

This repository contains an implementation of the **Pedersen Verifiable Secret Sharing (VSS)** scheme. The Pedersen VSS scheme provides a way to securely share a secret among multiple participants, ensuring that the secret can be reconstructed only when a certain minimum number of participants (threshold) combine their shares. This implementation is based on the work of **Pedersen (1991)**.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Implementation Details](#implementation-details)
- [References](#references)

## Introduction

**Pedersen's Verifiable Secret Sharing (VSS)** is a cryptographic scheme that allows a secret to be shared among `n` participants such that:
1. Any group of at least `t` participants can reconstruct the secret (`t` is the threshold).
2. Fewer than `t` participants cannot learn anything about the secret.
3. The validity of each share can be verified publicly without revealing the secret.

This scheme ensures both **secrecy** and **verifiability**, meaning that the secret is protected, and each participant can verify the correctness of their share without additional interaction.

## Features

- **Non-interactive**: Participants can verify the correctness of their shares without communication.
- **Threshold-based**: The secret can only be reconstructed with a minimum number of shares (`t`).
- **Public commitments**: Public commitments are generated and used to verify the validity of the shares.

## Requirements

To run this implementation, you'll need:

1. **Java**: Ensure you have a Java runtime environment (JRE) or a Java development kit (JDK).
2. **JPBC Library**: The implementation relies on the **Java Pairing-Based Cryptography (JPBC)** library for elliptic curve and pairing operations.
   - [JPBC Official Website](http://gas.dia.unisa.it/projects/jpbc/)

## Usage

1. Clone or download this repository.
2. Make sure JPBC is included in your classpath.
3. Create a properties file named `a.properties` for JPBC pairing parameters, or modify the `PairingFactory.getPairingParameters` line in the code to point to an appropriate parameter file.
4. Compile and run the `PedersenVSS` class.

### Example Commands

```bash
# Compile the code
javac -cp jpbc.jar PedersenVSS.java

# Run the code
java -cp .:jpbc.jar PedersenVSS
```

### Sample Output

```bash
Generator g in G1: [Some elliptic curve point g]
Generator h in G1: [Some elliptic curve point h]
Share Index: 1
Value1 (f_x): ...
Value2 (g_x): ...
Commitment: [...]
Validation Result: valid
...
Original Secret: [secret]
Reconstructed Secret: [reconstructed secret]
Secret reconstruction: success
```

 
