#pragma once

#include <stdint.h>
#include <stdbool.h>

// RSA16: RSA with 16-bit keys
typedef struct {
    uint16_t n;
    uint16_t e;
    uint16_t d;
    uint8_t IV_enc;
    uint8_t IV_dec;
} RSA16;

// Initialize the RSA16 structure with the given keys and IV
void RSA16_Init( RSA16* rsa, uint16_t n, uint16_t e, uint16_t d, uint8_t iv = 0 );

// Reset the IV for encryption and decryption
void RSA16_ResetIV( RSA16* rsa, uint8_t iv );

// Encrypt a single byte with public key(n, e)
uint16_t RSA16_Encrypt( RSA16* rsa, uint8_t message );

// Decrypt a single byte with private key(n, d)
uint8_t RSA16_Decrypt( RSA16* rsa, uint16_t cipher );

// Encrypt an array of bytes with public key(n, e)
void RSA16_EncryptBytes( RSA16* rsa, const uint8_t* message, size_t message_len, uint8_t* cipher );

// Decrypt an array of bytes with private key(n, d)
void RSA16_DecryptBytes( RSA16* rsa, const uint8_t* cipher, size_t cipher_len, uint8_t* message );

// Sign a message with private key(n, d)
uint16_t RSA16_Sign( RSA16* rsa, uint8_t message );

// Verify a signature with public key(n, e)
uint8_t RSA16_Verify( RSA16* rsa, uint16_t signature );

// Verify a signature with public key(n, e) and match it with the message
bool RSA16_ValidateSignature( RSA16* rsa, uint8_t message, uint16_t signature );

// Sign an array of bytes with private key(n, d)
void RSA16_SignBytes( RSA16* rsa, const uint8_t* message, size_t message_len, uint8_t* cipher );

// Verify an array of bytes with public key(n, e)
void RSA16_VerifyBytes( RSA16* rsa, const uint8_t* cipher, size_t cipher_len, uint8_t* message );

// Verify the signature with public key(n, e) and match it with the message
bool RSA16_ValidateSignature( RSA16* rsa, uint8_t message, uint16_t signature );

// Verify the signature with public key(n, e) and match it with the message
bool RSA16_ValidateSignatureBytes( RSA16* rsa, const uint8_t* message, size_t message_len, const uint8_t* signature );
