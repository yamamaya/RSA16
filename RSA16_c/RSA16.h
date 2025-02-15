#pragma once

#include <stdint.h>
#include <stdbool.h>

// ********** RSA16 Structure **********

// RSA16: RSA with 16-bit keys
typedef struct {
    uint16_t n;      // Modulus (used for all operations)
    uint16_t e;      // Public exponent (used for encryption and verification)
    uint16_t d;      // Private exponent (used for decryption and signing)
    uint8_t IV_enc;  // Initialization vector for encryption
    uint8_t IV_dec;  // Initialization vector for decryption
} RSA16;


// Default initialization vector for encryption and decryption, do not use Zero as IV!
#define RSA16_DEFAULT_IV 0x5C  

// ********** Initialization **********

// Initialize the RSA16 structure with the given keys and IV
// If you use only public key for encryption and verification, set d to 0.
// If you use only private key for decryption and signing, set e to 0.
void RSA16_Init( RSA16* rsa, uint16_t n, uint16_t e, uint16_t d, uint8_t iv = RSA16_DEFAULT_IV );

// Reset the IV for encryption and decryption
// There is a definition for a default initialization vector RSA16_DEFAULT_IV, use that instead of zero.
void RSA16_ResetIV( RSA16* rsa, uint8_t iv );


// ********** Encryption **********

// Encrypt a single byte with public key(n, e)
uint16_t RSA16_Encrypt( RSA16* rsa, uint8_t message );

// Encrypt an array of bytes with public key(n, e)
// The cipher length is twice the message length
void RSA16_EncryptBytes( RSA16* rsa, const uint8_t* message, size_t message_len, uint8_t* cipher );


// ********** Decryption **********

// Decrypt a single byte with private key(n, d)
uint8_t RSA16_Decrypt( RSA16* rsa, uint16_t cipher );

// Decrypt an array of bytes with private key(n, d)
// The message length is half the cipher length
void RSA16_DecryptBytes( RSA16* rsa, const uint8_t* cipher, size_t cipher_len, uint8_t* message );


// ********** Signing **********

// Sign a message with private key(n, d)
uint16_t RSA16_Sign( RSA16* rsa, uint8_t message );

// Sign an array of bytes with private key(n, d)
// The signature length is twice the message length
void RSA16_SignBytes( RSA16* rsa, const uint8_t* message, size_t message_len, uint8_t* signature );


// ********** Verification and Validation **********

// Verify a signature with public key(n, e)
uint8_t RSA16_Verify( RSA16* rsa, uint16_t signature );

// Verify a signature with public key(n, e) and match it with the message
// Returns true if the signature is valid
bool RSA16_ValidateSignature( RSA16* rsa, uint8_t message, uint16_t signature );

// Verify a signature with public key(n, e)
// The message length is half the signature length
void RSA16_VerifyBytes( RSA16* rsa, const uint8_t* signature, size_t signature_len, uint8_t* message );

// Verify the signature with public key(n, e) and match it with the message
// Returns true if the signature is valid
bool RSA16_ValidateSignatureBytes( RSA16* rsa, const uint8_t* message, size_t message_len, const uint8_t* signature );
