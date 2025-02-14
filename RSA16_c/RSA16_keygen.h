#pragma once

// This file provides the implementation of the RSA16 key generation functions.
// It will be not necessary if you need only encryption and decryption functions.

#include <stdint.h>
#include "RSA16.h"

// Initialize the RSA16 structure with a random key
void RSA16_InitWithRandomKey( RSA16* rsa );

// Generate RSA keys
void RSA16_GenerateKeys( uint16_t* n, uint16_t* e, uint16_t* d );
