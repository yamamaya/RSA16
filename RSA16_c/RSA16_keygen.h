#pragma once

#include <stdint.h>
#include "RSA16.h"

// Initialize the RSA16 structure with a random key
void RSA16_InitWithRandomKey( RSA16* rsa );

// Generate RSA keys
void RSA16_GenerateKeys( uint16_t* n, uint16_t* e, uint16_t* d );
