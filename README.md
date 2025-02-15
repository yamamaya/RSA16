# RSA16

RSA16 is a minimalistic implementation of RSA encryption using only 16-bit keys. It is highly insecure by modern cryptographic standards but may be useful in situations where minimal security is preferable to no security at all.

## Features

- 16-bit RSA key generation
- Basic encryption and decryption
- Signing and verification
- Simple implementation of CBC mode
- C and C# implementations
- Extremely lightweight
- Educational purposes or low-security applications

## Security Warning

**DO NOT USE RSA16 FOR SENSITIVE DATA.**

Due to its extremely small key size, RSA16 is trivially breakable using brute-force methods or simple cryptanalysis techniques. It is provided as an educational tool or for scenarios where full cryptographic security is unnecessary.

## Usage

### Generating Keys (C)
```c
uint16_t n, e, d;
RSA16_GenerateKeys( &n, &e, &d );
```

### Generating Keys (C#)
```csharp
(UInt16 n, UInt16 e, UInt16 d) = RSA16.GenerateKeys();
```

### Create RSA16 instance (C)
```c
RSA16 rsa;
RSA16_Init( &rsa, n, e, d );
```

### Create RSA16 instance (C#)
```csharp
RSA16 rsa = new RSA16( n, e, d );
```

### Encrypting a Message (C)
```c
uint8_t* message = (uint8_t*)malloc( MESSAGE_SIZE );
uint8_t* cipher = (uint8_t*)malloc( MESSAGE_SIZE * 2 );
RSA16_EncryptBytes( &rsa, message, MESSAGE_SIZE, cipher );
```

### Encrypting a Message (C#)
```csharp
byte[] message = new byte[MESSAGE_SIZE];
byte[] chiper = rsa16.Encrypt( message );
```

### Decrypting a Message
```c
uint8_t* decrypted = (uint8_t*)malloc( MESSAGE_SIZE );
RSA16_DecryptBytes( &rsa, cipher, MESSAGE_SIZE * 2, decrypted );
```

### Decrypting a Message (C#)
```csharp
byte[] decrypted = rsa16.Decrypt( chiper );
```

## Limitations

- Easily breakable
- No advanced cryptographic protections

## License

RSA16 is released under the 2-clause BSD license. See `LICENSE` for more information.

## Disclaimer

I am not responsible for any security issues that may arise from the use of this library.
