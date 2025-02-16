// This file provides the implementation of the RSA16 key generation functions.
// It will be not necessary if you need only encryption and decryption functions.

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "RSA16.h"
#include "RSA16_keygen.h"

static uint16_t GenerateRandomPrime( uint16_t minValue, uint16_t maxValue );
static bool IsPrime( uint16_t number );
static uint16_t GenerateRandomE( uint16_t phi_n );
static uint16_t ModularInverse( uint16_t a, uint16_t m );
static uint16_t ExtendedGcd( uint16_t a, uint16_t b, int16_t* x, int16_t* y );

// Initialize the RSA16 structure with a random key
void RSA16_InitWithRandomKey( RSA16* rsa ) {
    RSA16_GenerateKeys( &rsa->n, &rsa->e, &rsa->d );
    rsa->IV_enc = 0;
    rsa->IV_dec = 0;
}

// Generate RSA keys
void RSA16_GenerateKeys( uint16_t* n, uint16_t* e, uint16_t* d ) {
    uint16_t p, q;
    do {
        p = GenerateRandomPrime( 16, 256 );
        do {
            q = GenerateRandomPrime( 16, 256 );
        } while ( p == q );
        *n = (uint16_t)( p * q );
    } while ( *n < 256 );

    uint16_t phi_n = ( p - 1 ) * ( q - 1 );
    *e = GenerateRandomE( phi_n );
    *d = (uint16_t)ModularInverse( *e, phi_n );
}

// Generate a random prime number in the range [minValue, maxValue]
static uint16_t GenerateRandomPrime( uint16_t minValue, uint16_t maxValue ) {
    while ( true ) {
        uint16_t candidate = (uint16_t)( rand() % ( maxValue - minValue + 1 ) + minValue );
        if ( IsPrime( candidate ) ) {
            return candidate;
        }
    }
}

// Check if a number is prime
static bool IsPrime( uint16_t number ) {
    if ( number <= 1 ) {
        return false;
    }
    if ( number <= 3 ) {
        return true;
    }
    if ( number % 2 == 0 || number % 3 == 0 ) {
        return false;
    }
    for ( uint16_t i = 5; i * i <= number; i += 6 ) {
        if ( number % i == 0 || number % ( i + 2 ) == 0 ) {
            return false;
        }
    }
    return true;
}

// Generate a random number e such that 1 < e < phi_n and gcd( e, phi_n ) = 1
static uint16_t GenerateRandomE( uint16_t phi_n ) {
    while ( true ) {
        uint16_t candidate = (uint16_t)( rand() % ( phi_n - 2 ) + 2 );
        int16_t x, y;
        if ( ExtendedGcd( candidate, phi_n, &x, &y ) == 1 ) {
            return candidate;
        }
    }
}

// Compute the modular inverse of a modulo m
static uint16_t ModularInverse( uint16_t a, uint16_t m ) {
    int16_t x, y;
    uint16_t g = ExtendedGcd( a, m, &x, &y );
    if ( g != 1 ) {
        fprintf( stderr, "modular inverse does not exist\n" );
        exit( EXIT_FAILURE );
    }
    return uint16_t( ( x % m + m ) % m );
}

// Extended Euclidean algorithm
static uint16_t ExtendedGcd( uint16_t a, uint16_t b, int16_t* x, int16_t* y ) {
    if ( a == 0 ) {
        *x = 0;
        *y = 1;
        return b;
    }
    int16_t x1, y1;
    uint16_t gcd = ExtendedGcd( b % a, a, &x1, &y1 );
    *x = y1 - ( b / a ) * x1;
    *y = x1;
    return gcd;
}