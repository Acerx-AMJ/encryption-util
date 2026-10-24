# Encryption Util
Encryption util is a CLI utility tool for encrypting files and archives safely using a password. It uses the XChaCha20-Poly1305 algorithm from libsodium.

## Building
This project depends on C++17 and [libsodium](https://github.com/jedisct1/libsodium). Here's an example of how to build it, assuming Linux/MacOS:
```bash
g++ -std=c++17 encryption-util.cpp -o util -O2 -lsodium
```

## Usage
Run the program with no arguments to check if it works:
```bash
./util
```
It should produce the usage instructions. You can also try viewing the example file:
```bash
./util --view example.encrypted
```
Input `1337secret!` and it should open the file and show its contents.

## Credits
This project was made by Daniel Vishnevsky and is licensed under MIT License.
