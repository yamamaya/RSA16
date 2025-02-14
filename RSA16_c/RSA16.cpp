#include <stdint.h>
#include "RSA16.h"

static int ModularExponentiation( uint16_t baseValue, uint16_t exponent, uint16_t modulus );

// Initialize the RSA16 structure with the given keys and IV
void RSA16_Init( RSA16* rsa, uint16_t n, uint16_t e, uint16_t d, uint8_t iv ) {
    rsa->n = n;
    rsa->e = e;
    rsa->d = d;
    rsa->IV_enc = iv;
    rsa->IV_dec = iv;
}

// Reset the IV for encryption and decryption
void RSA16_ResetIV( RSA16* rsa, uint8_t iv ) {
	rsa->IV_enc = iv;
	rsa->IV_dec = iv;
}

// Encrypt a single byte
uint16_t RSA16_Encrypt( RSA16* rsa, uint8_t message ) {
    return (uint16_t)ModularExponentiation( message, rsa->e, rsa->n );
}

// Decrypt a single byte
uint8_t RSA16_Decrypt( RSA16* rsa, uint16_t cipher ) {
    return (uint8_t)ModularExponentiation( cipher, rsa->d, rsa->n );
}

// Encrypt an array of bytes
void RSA16_EncryptBytes( RSA16* rsa, const uint8_t* message, size_t message_len, uint8_t* cipher ) {
    size_t nChars = message_len;
    uint8_t c_prev = rsa->IV_enc;
    size_t p = 0;
    for ( size_t i = 0; i < nChars; i++ ) {
		// Encrypt the message byte
        uint16_t c = (uint16_t)ModularExponentiation( message[ i ], rsa->e, rsa->n );
		// Store the low byte
        cipher[ p ] = (uint8_t)( c & 0xff );
        cipher[ p ] ^= c_prev;
        c_prev = cipher[ p ];
        p++;
		// Store the high byte
        cipher[ p ] = (uint8_t)( c >> 8 );
        cipher[ p ] ^= c_prev;
        c_prev = cipher[ p ];
        p++;
    }
	// Update the IV for next encryption
    rsa->IV_enc = c_prev;
}

// Decrypt an array of bytes
void RSA16_DecryptBytes( RSA16* rsa, const uint8_t* cipher, size_t cipher_len, uint8_t* message ) {
    size_t nChars = cipher_len / 2;
    uint8_t c_prev = rsa->IV_dec;
    size_t p = 0;
    for ( size_t i = 0; i < nChars; i++ ) {
		// Retrieve the low byte
        uint8_t cl = cipher[ p ] ^ c_prev;
        c_prev = cipher[ p ];
        p++;
		// Retrieve the high byte
        uint8_t ch = cipher[ p ] ^ c_prev;
        c_prev = cipher[ p ];
        p++;
		// Decrypt the message byte
        uint16_t c = (uint16_t)( cl | ( ch << 8 ) );
        message[ i ] = (uint8_t)ModularExponentiation( c, rsa->d, rsa->n );
    }
	// Update the IV for next decryption
    rsa->IV_dec = c_prev;
}

// Modular exponentiation
static int ModularExponentiation( uint16_t baseValue, uint16_t exponent, uint16_t modulus ) {
    uint16_t result = 1;
    uint16_t power = baseValue % modulus;
    while ( exponent > 0 ) {
        if ( exponent & 1 ) {
            result = (uint16_t)( ( (uint32_t)result * (uint32_t)power ) % modulus );
        }
        power = (uint16_t)( ( (uint32_t)power * (uint32_t)power ) % modulus );
        exponent >>= 1;
    }
    return result;
}
