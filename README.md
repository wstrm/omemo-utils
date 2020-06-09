# omemo-utils [![builds.sr.ht status](https://builds.sr.ht/~wstrm/omemo-utils.svg)](https://builds.sr.ht/~wstrm/omemo-utils?)

Utilities for OMEMO media sharing.

## Usage

```
ξ omut
Usage: ./omut [-d] [-o FILE] URL
```

### Encrypt

Encrypt the file and send the output to a file using shell redirection:

```
ξ omut file:///home/me/file.txt > encrypted.aes
```

Encrypt the file and write the output to a file:
```
ξ omut -o encrypted.aes file:///home/me/file.txt
```

### Decrypt

Decrypt the data located at the URL and send the output to a file using shell
redirection:

```
ξ omut -d aesgcm://example.org/file.aes#abc...def > decrypted.txt
```

Decrypt the data located at the URL and write the output to a file:
```
ξ omut -d -o decrypted.txt aesgcm://example.org/file.aes#abc...def
```
