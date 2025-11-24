ESC: An Enhanced-Keyed Shiftmerge Cipher Inspired by a Product-Based Symmetric Algorithm with Encrypted Space Mapping and Noise Injection

Overview

This repository contains two tools for working with the ESC encryption scheme:

clean.py
A compact, GUI-based encryption/decryption tool using Tkinter. Ideal for quick testing and manual use.

process.py
A command-line implementation that follows the full ESC process flow. Intended for debugging, demonstrations, and analysis.

=============================================================================================================================================

Instructions on how to use both clean.py and process.py:

Encryption
- during encryption, we must provide plaintext, passphrase, and noise bytes to inject.

Sample of encryption run:

Enter plaintext: h3ll0 MoonDo3!
Enter passphrase: MAPUA
Noise bytes to inject (default 8): 16

Output of encryption run:
{
    "salt": "/ybjk34LJ2LaUKLIaGc+wA==",
    "nonce": "yo+W8yuF9xp2X1cI",
    "main": "a1VzOsUfd2pxWHVoNw==",
    "space": "ZQ==",
    "flags": "VLE32x4rpYupviuO6g==",
    "case": "ndu8v4IHrFindX6S2g==",
    "noiseL": "CRoDO9k7vt1TxlLKF1D57w==",
    "noiseR": "C80nc7RqrsjtQls3miWM2Q=="
}

-------------------------------------------------------------------------------------------------------------------------------------------

Decryption
- During decryption, the user have to enter the passphrase, and then, the user will be provided two options: Paste JSON (copy/paste the json package from encryption process) and Load the json package from the cipher.json file.

Sample of decryption run:

Enter passphrase: MAPUA

Decrypt options: 
    1.  Paste JSON (multi-line allowed)
    2.  Load from cipher.json file
Choose 1 or 2: 2
Loaded cipher.json

output: 

Recovered plaintext: h3ll0 MoonDo3!