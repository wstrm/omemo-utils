# omemo-utils [![builds.sr.ht status](https://builds.sr.ht/~wstrm/omemo-utils.svg)](https://builds.sr.ht/~wstrm/omemo-utils?)

Utilities for OMEMO media sharing.

## Usage

```
ξ omut
Usage: omut [-d] URL
```

### Encrypt

```
ξ omut file:///home/me/file.txt > encrypted.aes
```

### Decrypt

```
ξ omut -d aesgcm://example.org/file.aes#abc...def > decrypted.txt
```
