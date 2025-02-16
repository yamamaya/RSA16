#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "RSA16.h"
#include "RSA16_sign.h"
#include "RSA16_keygen.h"

#define MESSAGE_SIZE 256

// RSA16 structure
static RSA16 rsa;

// Sample message
static char sample[] = "The quick, brown fox jumps over a lazy dog. DJs flock by when MTV ax quiz prog. Junk MTV quiz graced by fox whelps. Bawds jog, flick quartz, vex nymphs. Waltz, bad nymph, for quick jigs vex! Fox nymphs grab quick-jived waltz. Brick quiz whangs jumpy veldt.";

// Dump bytes to the console
static void DumpBytes( const uint8_t* bytes, size_t count ) {
    for ( size_t i = 0; i < count; i++ ) {
        if ( i > 0 && i % 16 == 0 ) {
            printf( "\n" );
        }
        printf( "%02X ", bytes[ i ] );
    }
    printf( "\n" );
}

// Test the RSA16 encryption and decryption
static bool Test1() {
    printf( "\n********** Test1 **********\n" );
    printf( "Encrypting by public key and decrypting by private key.\n" );

    // Allocate memory
    uint8_t* cipher = (uint8_t*)malloc( MESSAGE_SIZE * 2 );
    uint8_t* decrypted = (uint8_t*)malloc( MESSAGE_SIZE );
    if ( cipher == NULL || decrypted == NULL ) {
        printf( "Memory allocation failed!\n" );
        return false;
    }

    const uint8_t* message = (const uint8_t*)sample;

    // Encrypt the message
    RSA16_EncryptBytes( &rsa, message, MESSAGE_SIZE, cipher );

    // Decrypt the message
    RSA16_DecryptBytes( &rsa, cipher, MESSAGE_SIZE * 2, decrypted );

    // Print the message, cipher, and decrypted message
    printf( "\nMessage: (%d bytes)\n", MESSAGE_SIZE );
    DumpBytes( message, MESSAGE_SIZE );

    printf( "\nCipher: (%d bytes)\n", MESSAGE_SIZE * 2 );
    DumpBytes( cipher, MESSAGE_SIZE * 2 );

    printf( "\nDecrypted message: (%d bytes)\n", MESSAGE_SIZE );
    DumpBytes( decrypted, MESSAGE_SIZE );

    // Print the decrypted message as a string
    printf( "\nDecrypted message (as string):\n" );
    for ( size_t i = 0; i < MESSAGE_SIZE; i++ ) {
        char c = decrypted[ i ];
        if ( c >= 32 && c <= 126 ) {
            printf( "%c", c );
        } else {
            printf( "." );
        }
    }
    printf( "\n" );

    // Check if the decryption was successful
    bool result;
    if ( memcmp( message, decrypted, MESSAGE_SIZE ) == 0 ) {
        printf( "\nDecryption successful!\n" );
        result = true;
    } else {
        printf( "\nDecryption failed!\n" );
        result = false;
    }

    // Free memory
    free( cipher );
    free( decrypted );

    return result;
}

// Test the RSA16 signing and verification
static bool Test2() {
    printf( "\n********** Test2 **********\n" );
    printf( "Signing and verifying the signature.\n" );

    uint8_t* signature = (uint8_t*)malloc( MESSAGE_SIZE * 2 );
    if ( signature == NULL ) {
        printf( "Memory allocation failed!\n" );
        return false;
    }

    const uint8_t* message = (const uint8_t*)sample;

    // Sign the message
    RSA16_SignBytes( &rsa, message, MESSAGE_SIZE, signature );
    printf( "\nSignature: (%d bytes)\n", MESSAGE_SIZE * 2 );
    DumpBytes( signature, MESSAGE_SIZE * 2 );

    // Verify the signature
    bool verified = RSA16_ValidateSignatureBytes( &rsa, message, MESSAGE_SIZE, signature );
    if ( verified ) {
        printf( "\nSignature verified!\n" );
    } else {
        printf( "\nSignature verification failed!\n" );
    }

    // Free memory
    free( signature );

    return verified;
}

// Test the RSA16 signing and verification with CRC
static bool Test3() {
    printf( "\n********** Test3 **********\n" );
    printf( "Signing and verifying the signature with CRC.\n" );

    const uint8_t* message = (const uint8_t*)sample;

    // Sign the message with CRC
    uint32_t sign_crc = RSA16_SignCRC( &rsa, message, MESSAGE_SIZE );
    printf( "\nCRC Signature: %08X\n", sign_crc );

    // Verify the signature with CRC
    bool verified_crc = RSA16_ValidateSignatureCRC( &rsa, message, MESSAGE_SIZE, sign_crc );
    if ( verified_crc ) {
        printf( "\nCRC Signature verified!\n" );
    } else {
        printf( "\nCRC Signature verification failed!\n" );
    }

    return verified_crc;
}

int main() {
    // Generate RSA keys
    uint16_t n, e, d;
    RSA16_GenerateKeys( &n, &e, &d );
    printf( "RSA16 keys generated:\n" );
    printf( "Modulus (n) = %d\n", n );
    printf( "Public exponent (e) = %d\n", e );
    printf( "Private exponent (d) = %d\n", d );

    // Initialize the RSA16 structure with the keys
    RSA16_Init( &rsa, n, e, d );

    bool result = Test1();

    result &= Test2();

    result &= Test3();

    printf( "\n********** Test finished **********\n" );
    if ( result ) {
        printf( "\nAll tests passed!\n" );
    } else {
        printf( "\nSome tests failed!\n" );
    }

    printf( "\nHit Enter to exit...\n" );
    getchar();

    return 0;
}
