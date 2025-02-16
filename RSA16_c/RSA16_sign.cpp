#include "RSA16.h"

static uint16_t CalculateCRC16( const uint8_t* data, size_t len );

// Sign a message with private key(n, d)
uint16_t RSA16_Sign( RSA16* rsa, uint8_t message ) {
    return ModularExponentiation( message, rsa->d, rsa->n );
}

// Verify a signature with public key(n, e)
uint8_t RSA16_Verify( RSA16* rsa, uint16_t signature ) {
    return (uint8_t)ModularExponentiation( signature, rsa->e, rsa->n );
}

// Verify the signature with public key(n, e) and match it with the message
bool RSA16_ValidateSignature( RSA16* rsa, uint8_t message, uint16_t signature ) {
    uint16_t m = (uint16_t)ModularExponentiation( signature, rsa->e, rsa->n );
    return m == message;
}

// Sign an array of bytes with private key(n, d)
void RSA16_SignBytes( RSA16* rsa, const uint8_t* message, size_t message_len, uint8_t* signature ) {
    size_t nChars = message_len;
    size_t p = 0;
    for ( size_t i = 0; i < nChars; i++ ) {
        // Encrypt the message byte
        uint16_t c = ModularExponentiation( message[ i ], rsa->d, rsa->n );
        // Store the low byte
        signature[ p ] = (uint8_t)( c & 0xff );
        p++;
        // Store the high byte
        signature[ p ] = (uint8_t)( c >> 8 );
        p++;
    }
}

// Verify a signature with public key(n, e)
void RSA16_VerifyBytes( RSA16* rsa, const uint8_t* signature, size_t signature_len, uint8_t* message ) {
    size_t nChars = signature_len / 2;
    size_t p = 0;
    for ( size_t i = 0; i < nChars; i++ ) {
        // Retrieve the low byte
        uint8_t cl = signature[ p ];
        p++;
        // Retrieve the high byte
        uint8_t ch = signature[ p ];
        p++;
        // Decrypt the message byte
        uint16_t c = (uint16_t)( cl | ( ch << 8 ) );
        message[ i ] = RSA16_Verify( rsa, c );
    }
}

// Verify the signature with public key(n, e) and match it with the message
bool RSA16_ValidateSignatureBytes( RSA16* rsa, const uint8_t* message, size_t message_len, const uint8_t* signature ) {
    size_t nChars = message_len;
    size_t p = 0;
    for ( size_t i = 0; i < nChars; i++ ) {
        // Retrieve the low byte
        uint8_t cl = signature[ p ];
        p++;
        // Retrieve the high byte
        uint8_t ch = signature[ p ];
        p++;
        // Decrypt the message byte
        uint16_t c = (uint16_t)( cl | ( ch << 8 ) );
        uint8_t m = RSA16_Verify( rsa, c );
        if ( m != message[ i ] ) {
            return false;
        }
    }
    return true;
}

// Calculate CRC16 and sign it with private key(n, d)
uint32_t RSA16_SignCRC( RSA16* rsa, const uint8_t* data, size_t len ) {
    uint16_t crc = CalculateCRC16( data, len );
    uint16_t lower = RSA16_Sign( rsa, (uint8_t)( crc & 0xff ) );
    uint16_t upper = RSA16_Sign( rsa, (uint8_t)( crc >> 8 ) );
    return ( (uint32_t)upper << 16 ) | lower;
}

// Verify the signature with public key(n, e) and match it with the CRC
bool RSA16_ValidateSignatureCRC( RSA16* rsa, const uint8_t* data, size_t len, uint32_t signature ) {
    uint16_t crc = CalculateCRC16( data, len );
    bool lower = RSA16_ValidateSignature( rsa, (uint8_t)( crc & 0xff ), (uint16_t)( signature & 0xffff ) );
    bool upper = RSA16_ValidateSignature( rsa, (uint8_t)( crc >> 8 ), (uint16_t)( signature >> 16 ) );
    return lower && upper;
}

// Calculate CRC16
static uint16_t CalculateCRC16( const uint8_t* data, size_t len ) {
    uint16_t crc = 0;
    for ( size_t i = 0; i < len; i++ ) {
        crc ^= data[ i ];
        for ( size_t j = 0; j < 8; j++ ) {
            if ( crc & 1 ) {
                crc = ( crc >> 1 ) ^ 0xA001;
            } else {
                crc = ( crc >> 1 );
            }
        }
    }
    return crc;
}