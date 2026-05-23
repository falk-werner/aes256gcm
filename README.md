[![Build](https://github.com/falk-werner/aes256gcm/actions/workflows/build.yml/badge.svg)](https://github.com/falk-werner/aes256gcm/actions/workflows/build.yml)

# AES256GCM

Command line tool to encrypt and decrypt files using AES256GCM.

## Usage

```bash
# encrypt
aes256gcm --encrypt -i plain.txt -o encrypted.bin -k secret

# decrypt
aes256gcm --decrypt -i encrypted.bin -o decrypted.txt -k secret

# encrypt inplace
aes256gcm --encrypt -i some.file -k secret

# decrypt inplace
aes256gcm --decrypt -i some.file -k secret
```

| Option | Argument | Description |
| ------ | -------- | ----------- |
| -e, --encrypt | - | Encrypt the file. |
| -d, --decrypt | - | Decrypt the file. |
| -p, --print | - | Print information about an encrypted file. |
| -i, --infile | PATH | Path of the input file. |
| -o, --outfile | PATH | Optional. Path of the output file. If not specified, file is encrypted / decrypted inplace. |
| -k, --key | STRING | Password used for encryption / descryption. |

## Build

```bash
cmake -B build
cmake --build build

# Run Unit Tests
cmake --build build --target test

# Install
sudo cmake --install build
```

## References

- https://docs.openssl.org/3.0/man3/EVP_KDF/
- https://docs.openssl.org/3.0/man3/EVP_EncryptInit/
- https://github.com/openssl/openssl/blob/master/providers/implementations/kdfs/pbkdf2.c
- https://github.com/majek/openssl/blob/master/demos/evp/aesgcm.c
