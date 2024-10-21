
# libharpia (Unofficial - Work In Progress)

This repository contains a Python-based simulation of the _libharpia_ cryptographic library, originally developed to secure Brazilian elections by CEPESC¹. The code simulates key cryptographic operations, such as hybrid key exchange, authenticated encryption, digital signatures, and key derivation using modern cryptographic algorithms available in Python.

**Disclaimer 1:** I started the implementation but hadn't got time to finish. It is still a work in progress with unfortunately no end in sight (due to my other commitments). The functions are not yet finished and do not implement all primitives as stated. I had to adapt a little to get a runnable code.

**Disclaimer 2:** This is a NON-OFFICIAL implementation because shamefully, the Brazilian government ignores [Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle) (_"the security of a cryptographic system shouldn't rely on the secrecy of the algorithm"_) and does not allow public auditing. 

## Features

-   **Hybrid Key Exchange (Simulated)**: Uses elliptic curve Diffie-Hellman (ECDH) to generate a shared encryption key.
-   **Authenticated Encryption**: Implements ChaCha20-Poly1305 for encryption, ensuring both confidentiality and integrity.
-   **Digital Signatures**: Uses Ed448 elliptic curve cryptography to sign messages.
-   **Key Derivation**: Uses the HKDF algorithm to derive cryptographic keys from a base key, salt, and additional info.

## Installation

1.  Clone the repository:
```bash
git clone https://github.com/AndreisPurim/libharpia.git
cd libharpia
```
2. Install the necessary dependencies:
```bash
pip install pynacl cryptography
```

## Usage

The main script `apis.py` demonstrates the key functionalities, simulating the API calls (originally not programmed in python):

-   **`init_encryption(k, NULL, 0, ct, ctl, pk, NULL)`**: Initializes the encryption key using elliptic curve Diffie-Hellman and HKDF.
-   **`encrypt(k, p, pl, c, cl, NULL)`**: Encrypts the plaintext using ChaCha20-Poly1305 authenticated encryption.
-   **`sign_buffer(b, bl, s, sl, pk)`**: Signs a message buffer using the Ed448 digital signature algorithm.
-   **`derive_key(sk, dk, salt, saltl, info, infol, NULL)`**: Derives a new key using the HKDF key derivation function.
## Cryptographic Concepts

This simulation uses Python cryptographic libraries to mimic _libharpia_'s core concepts:

-   **Elliptic Curve Diffie-Hellman (ECDH)**: A public-key cryptographic key exchange method used to securely generate a shared encryption key.
-   **ChaCha20-Poly1305**: A stream cipher combined with a Message Authentication Code (MAC) for authenticated encryption.
-   **Ed448 Digital Signatures**: A signature algorithm that provides strong security and is part of modern cryptographic standards.
-   **HKDF (HMAC-based Key Derivation Function)**: A cryptographic algorithm that derives secure keys from a shared secret, salt, and additional information. (Note to self: I'm yet to reread the paper and understand how their KDF differs from HKDF).

## License

This project is licensed under the MIT License.

## Acknowledgements

Thanks to the authors of the original paper.

[1] 1. Rodrigo Pacheco, Douglas Braga, Iago Passos, Thiago Araújo, Vinícius Lagrota, and Murilo Coutinho. 2022. libharpia: a New Cryptographic Library for Brazilian Elections. Anais do XXII Simpósio Brasileiro de Segurança da Informação e de Sistemas Computacionais (SBSeg 2022), 250–263. https://doi.org/10.5753/sbseg.2022.224098


