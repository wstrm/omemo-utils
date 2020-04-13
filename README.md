# omemo-utils

**IN PROGRESS**: Below follows how the usage _should_ be like in the future.

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
