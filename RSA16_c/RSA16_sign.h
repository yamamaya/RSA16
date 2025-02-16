#pragma once

#include "RSA16.h"

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

// Calculate CRC16 and sign it with private key(n, d)
uint32_t RSA16_SignCRC( RSA16* rsa, const uint8_t* data, size_t len );

// Verify the signature with public key(n, e) and match it with the CRC16
bool RSA16_ValidateSignatureCRC( RSA16* rsa, const uint8_t* data, size_t len, uint32_t signature );