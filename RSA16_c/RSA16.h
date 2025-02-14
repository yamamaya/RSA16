#pragma once

#include <stdint.h>

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

// Encrypt a single byte
uint16_t RSA16_Encrypt( RSA16* rsa, uint8_t message );

// Decrypt a single byte
uint8_t RSA16_Decrypt( RSA16* rsa, uint16_t cipher );

// Encrypt an array of bytes
void RSA16_EncryptBytes( RSA16* rsa, const uint8_t* message, size_t message_len, uint8_t* cipher );

// Decrypt an array of bytes
void RSA16_DecryptBytes( RSA16* rsa, const uint8_t* cipher, size_t cipher_len, uint8_t* message );