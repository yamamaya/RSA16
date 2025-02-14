#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "RSA16.h"
#include "RSA16_keygen.h"

static uint16_t GenerateRandomPrime( int minValue, int maxValue );
static bool IsPrime( uint16_t number );
static uint16_t GenerateRandomE( int phi_n );
static int ModularInverse( int a, int m );
static int ExtendedGcd( int a, int b, int* x, int* y );

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

    int phi_n = ( p - 1 ) * ( q - 1 );
    *e = GenerateRandomE( phi_n );
    *d = (uint16_t)ModularInverse( *e, phi_n );
}

// Generate a random prime number in the range [minValue, maxValue]
static uint16_t GenerateRandomPrime( int minValue, int maxValue ) {
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
static uint16_t GenerateRandomE( int phi_n ) {
    while ( true ) {
        uint16_t candidate = (uint16_t)( rand() % ( phi_n - 2 ) + 2 );
        int x, y;
        if ( ExtendedGcd( candidate, phi_n, &x, &y ) == 1 ) {
            return candidate;
        }
    }
}

// Compute the modular inverse of a modulo m
static int ModularInverse( int a, int m ) {
    int x, y;
    int g = ExtendedGcd( a, m, &x, &y );
    if ( g != 1 ) {
        fprintf( stderr, "modular inverse does not exist\n" );
        exit( EXIT_FAILURE );
    }
    return ( x % m + m ) % m;
}

// Extended Euclidean algorithm
static int ExtendedGcd( int a, int b, int* x, int* y ) {
    if ( a == 0 ) {
        *x = 0;
        *y = 1;
        return b;
    }
    int x1, y1;
    int gcd = ExtendedGcd( b % a, a, &x1, &y1 );
    *x = y1 - ( b / a ) * x1;
    *y = x1;
    return gcd;
}