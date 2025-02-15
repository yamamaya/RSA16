#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "RSA16.h"
#include "RSA16_keygen.h"

#define MESSAGE_SIZE 256

static char sample[] = "The quick, brown fox                                     when MTV ax quiz prog. Junk MTV quiz graced by fox whelps. Bawds jog, flick quartz, vex nymphs. Waltz, bad nymph, for quick jigs vex! Fox nymphs grab quick-jived waltz. Brick quiz whangs jumpy veldt.";

static void DumpBytes( const uint8_t* bytes, size_t count ) {
    for ( size_t i = 0; i < count; i++ ) {
        if ( i > 0 && i % 16 == 0 ) {
            printf( "\n" );
        }
        printf( "%02X ", bytes[ i ] );
    }
    printf( "\n" );
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
    RSA16 rsa;
    RSA16_Init( &rsa, n, e, d );

    // Allocate memory for the message, cipher, and decrypted message
    uint8_t* message = (uint8_t*)malloc( MESSAGE_SIZE );
    uint8_t* cipher = (uint8_t*)malloc( MESSAGE_SIZE * 2 );
    uint8_t* decrypted = (uint8_t*)malloc( MESSAGE_SIZE );
    uint8_t* signature = (uint8_t*)malloc( MESSAGE_SIZE * 2 );

    if ( message == NULL || cipher == NULL || decrypted == NULL || signature == NULL ) {
        printf( "Memory allocation failed!\n" );
        return 1;
    }

    // Copy the sample message to the message buffer
    memcpy( message, sample, MESSAGE_SIZE );

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
    if ( memcmp( message, decrypted, MESSAGE_SIZE ) == 0 ) {
        printf( "\nDecryption successful!\n" );
    } else {
        printf( "\nDecryption failed!\n" );
    }

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
    free( message );
    free( cipher );
    free( decrypted );
    free( signature );

    printf( "\nHit Enter to exit...\n" );
    getchar();

    return 0;
}
