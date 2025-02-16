using System;
using System.Security.Cryptography;

namespace OaktreeLab.Utils.Cryptography {
    /// <summary>
    /// 16-bit RSA encryptor
    /// </summary>
    class RSA16 {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <remarks>
        /// Generates a new 16-bit RSA encryptor with random keys.
        /// </remarks>
        /// <exception cref="Exception"></exception>
        public RSA16() {
            (n, e, d) = GenerateKeys();
            this.IV_enc = DefaultIV;
            this.IV_dec = DefaultIV;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <remarks>
        /// Initializes an RSA encryptor with the specified keys (n, e, d).
        /// If you use only public key for encryption and verification, set d to 0.
        /// If you use only private key for decryption and signing, set e to 0.
        /// </remarks>
        /// <param name="n"></param>
        /// <param name="e"></param>
        /// <param name="d"></param>
        public RSA16( UInt16 n, UInt16 e, UInt16 d ) : this( n, e, d, DefaultIV ) {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <remarks>
        /// Initializes an RSA encryptor with the specified keys (n, e, d) and the specified CBC mode initialization vector.
        /// If you use only public key for encryption and verification, set d to 0.
        /// If you use only private key for decryption and signing, set e to 0.
        /// </remarks>
        /// <param name="n"></param>
        /// <param name="e"></param>
        /// <param name="d"></param>
        /// <param name="iv"></param>
        public RSA16( UInt16 n, UInt16 e, UInt16 d, byte iv ) {
            this.n = n;
            this.e = e;
            this.d = d;
            IV_enc = iv;
            IV_dec = iv;
        }

        /// <summary>
        /// Reset the CBC mode initialization vector
        /// </summary>
        public void ResetIV() {
            ResetIV( DefaultIV );
        }

        /// <summary>
        /// Reset the CBC mode initialization vector
        /// </summary>
        /// <param name="iv"></param>
        public void ResetIV( byte iv ) {
            IV_enc = iv;
            IV_dec = iv;
        }

        /// <summary>
        /// Default initialization vector
        /// </summary>
        private const byte DefaultIV = 0x5C;

        /// <summary>
        /// Modulus
        /// </summary>
        private readonly UInt16 n;

        /// <summary>
        /// Public exponent
        /// </summary>
        private readonly UInt16 e;

        /// <summary>
        /// Private exponent
        /// </summary>
        private readonly UInt16 d;

        /// <summary>
        /// Public key (n, e)
        /// </summary>
        public (UInt16, UInt16) PublicKey => (n, e);

        /// <summary>
        /// Private key (n, d)
        /// </summary>
        public (UInt16, UInt16) PrivateKey => (n, d);

        /// <summary>
        /// Set of keys (n, e, d)
        /// </summary>
        public (UInt16, UInt16, UInt16) Key => (n, e, d);

        /// <summary>
        /// IV for encryption
        /// </summary>
        private byte IV_enc = 0;

        /// <summary>
        /// IV for decryption
        /// </summary>
        private byte IV_dec = 0;

        #region Functions for key generation

        /// <summary>
        /// Generate keys
        /// </summary>
        /// <returns>Tuple of key components (n, e, d)</returns>
        public static (UInt16 n, UInt16 e, UInt16 d) GenerateKeys() {
            UInt16 n, e, d;
            // Generate two 16-bit primes p and q
            UInt16 p, q;
            do {
                p = GenerateRandomPrime( 16, 256 );
                do {
                    q = GenerateRandomPrime( 16, 256 );
                } while ( p == q ); // Make sure p and q are different
                n = (UInt16)( p * q );
            } while ( n < 256 );

            int phi_n = ( p - 1 ) * ( q - 1 );

            // Generate public exponent e
            e = GenerateRandomE( phi_n );

            // Generate private exponent d
            d = (UInt16)ModularInverse( e, phi_n );

            return (n, e, d);
        }

        /// <summary>
        /// Generate a random prime number
        /// </summary>
        /// <param name="minValue"></param>
        /// <param name="maxValue"></param>
        /// <returns></returns>
        private static UInt16 GenerateRandomPrime( int minValue, int maxValue ) {
            while ( true ) {
                UInt16 candidate = (UInt16)RandomNumberGenerator.GetInt32( minValue, maxValue );
                if ( IsPrime( candidate ) ) {
                    return candidate;
                }
            }
        }

        /// <summary>
        /// Check if a number is prime
        /// </summary>
        /// <param name="number"></param>
        /// <returns></returns>
        private static bool IsPrime( UInt16 number ) {
            if ( number <= 1 ) {
                return false;
            }
            if ( number <= 3 ) {
                return true;
            }
            if ( number % 2 == 0 || number % 3 == 0 ) {
                return false;
            }
            for ( UInt16 i = 5 ; i * i <= number ; i += 6 ) {
                if ( number % i == 0 || number % ( i + 2 ) == 0 ) {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Generate a random public exponent e
        /// </summary>
        /// <param name="phi_n"></param>
        /// <returns></returns>
        private static UInt16 GenerateRandomE( int phi_n ) {
            while ( true ) {
                UInt16 candidate = (UInt16)RandomNumberGenerator.GetInt32( 2, phi_n );
                if ( ExtendedGcd( candidate, phi_n, out _, out _ ) == 1 ) {
                    return candidate;
                }
            }
        }

        /// <summary>
        /// Modular inverse
        /// </summary>
        /// <param name="a"></param>
        /// <param name="m"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        private static int ModularInverse( int a, int m ) {
            int g = ExtendedGcd( a, m, out int x, out _ );
            if ( g != 1 ) {
                throw new Exception( "modular inverse does not exist" );
            }
            return ( x % m + m ) % m;
        }

        /// <summary>
        /// Extended Euclidean algorithm
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        private static int ExtendedGcd( int a, int b, out int x, out int y ) {
            if ( a == 0 ) {
                x = 0;
                y = 1;
                return b;
            }
            int x1, y1;
            int gcd = ExtendedGcd( b % a, a, out x1, out y1 );
            x = y1 - (int)( b / a ) * x1;
            y = x1;
            return gcd;
        }

        #endregion

        /// <summary>
        /// Encrypt a message with the public key(n, e)
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public UInt16 Encrypt( byte message ) {
            return (UInt16)ModularExponentiation( message, e, n );
            //// Basic implementation
            //int c = 1;
            //for ( int i = 0 ; i < e ; i++ ) {
            //    c = ( c * message ) % n;
            //}
            //return (UInt16)c;
        }

        /// <summary>
        /// Decrypt a cipher with the private key(n, d)
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns></returns>
        public byte Decrypt( UInt16 cipher ) {
            return (byte)ModularExponentiation( cipher, d, n );
            //// Basic implementation
            //int m = 1;
            //int c = (int)cipher;
            //for ( int i = 0 ; i < d ; i++ ) {
            //    m = ( m * c ) % n;
            //}
            //return (byte)m;
        }

        /// <summary>
        /// Encrypt a byte array with the public key(n, e)
        /// </summary>
        /// <remarks>
        /// CBC mode encryption is performed.
        /// The initialization vector is updated each time.
        /// CBC has its own implementation.
        /// </remarks>
        /// <param name="message"></param>
        /// <returns></returns>
        public byte[] Encrypt( byte[] message ) {
            int nChars = message.Length;
            byte c_prev = IV_enc;
            byte[] cipher = new byte[ nChars * 2 ];
            int p = 0;
            for ( int i = 0 ; i < nChars ; i++ ) {
                // Encrypt the message
                UInt16 c = (UInt16)ModularExponentiation( (byte)( message[ i ] ^ c_prev ), e, n );
                // Store lower byte first
                cipher[ p ] = (byte)( ( c & 0xff ) ^ c_prev );
                p++;
                // Store higher byte next
                cipher[ p ] = (byte)( ( c >> 8 ) ^ c_prev );
                c_prev = (byte)( message[ i ] ^ cipher[ p ] );
                p++;
            }
            // Update the initialization vector for the next block
            IV_enc = c_prev;
            return cipher;
        }

        /// <summary>
        /// Decrypt a byte array with the private key(n, d)
        /// </summary>
        /// <remarks>
        /// CBC mode decryption is performed.
        /// The initialization vector is updated each time.
        /// CBC has its own implementation.
        /// </remarks>
        /// <param name="cipher"></param>
        /// <returns></returns>
        public byte[] Decrypt( byte[] cipher ) {
            int nChars = cipher.Length / 2;
            byte[] message = new byte[ nChars ];
            byte c_prev = IV_dec;
            int p = 0;
            for ( int i = 0 ; i < nChars ; i++ ) {
                // Retrieve lower byte first
                byte cl = (byte)( cipher[ p ] ^ c_prev );
                p++;
                // Retrieve higher byte next
                byte ch = (byte)( cipher[ p ] ^ c_prev );
                // Combine the two bytes
                UInt16 c = (UInt16)( cl | ( ch << 8 ) );
                // Decrypt the message
                message[ i ] = (byte)(ModularExponentiation( c, d, n ) ^ c_prev );
                c_prev = (byte)( message[ i ] ^ cipher[ p ] );
                p++;
            }
            // Update the initialization vector for the next block
            IV_dec = c_prev;
            return message;
        }

        /// <summary>
        /// Sign a message with the private key(n, d)
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public UInt16 Sign( byte message ) {
            return (UInt16)ModularExponentiation( message, d, n );
        }

        /// <summary>
        /// Verify a signature with the public key(n, e)
        /// </summary>
        /// <param name="signature"></param>
        /// <returns></returns>
        public byte Verify( UInt16 signature ) {
            return (byte)ModularExponentiation( signature, e, n );
        }

        /// <summary>
        /// Verify a signature with public key(n, e) and match it with the message
        /// </summary>
        /// <param name="message"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public bool Verify( byte message, UInt16 signature ) {
            byte decryptedSignature = (byte)ModularExponentiation( signature, e, n );
            return message == decryptedSignature;
        }

        /// <summary>
        /// Sign a byte array with the private key(n, d)
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public byte[] Sign( byte[] message ) {
            int nChars = message.Length;
            byte[] signature = new byte[ nChars * 2 ];
            int p = 0;
            for ( int i = 0 ; i < nChars ; i++ ) {
                UInt16 s = (UInt16)ModularExponentiation( message[ i ], d, n );
                signature[ p ] = (byte)( s & 0xff );
                p++;
                signature[ p ] = (byte)( s >> 8 );
                p++;
            }
            return signature;
        }

        /// <summary>
        /// Verify a byte array signature with the public key(n, e)
        /// </summary>
        /// <param name="signature"></param>
        /// <returns></returns>
        public byte[] Verify( byte[] signature ) {
            int nChars = signature.Length / 2;
            byte[] message = new byte[ nChars ];
            int p = 0;
            for ( int i = 0 ; i < nChars ; i++ ) {
                byte sl = signature[ p ];
                p++;
                byte sh = signature[ p ];
                p++;
                UInt16 s = (UInt16)( sl | ( sh << 8 ) );
                message[ i ] = (byte)ModularExponentiation( s, e, n );
            }
            return message;
        }

        /// <summary>
        /// Verify a byte array signature with the public key(n, e) and match it with the message
        /// </summary>
        /// <param name="message"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public bool Verify( byte[] message, byte[] signature ) {
            if ( message.Length * 2 != signature.Length ) {
                return false;
            }

            int nChars = message.Length;
            int p = 0;
            for ( int i = 0 ; i < nChars ; i++ ) {
                byte sl = signature[ p ];
                p++;
                byte sh = signature[ p ];
                p++;
                UInt16 s = (UInt16)( sl | ( sh << 8 ) );
                byte decryptedMessageByte = (byte)ModularExponentiation( s, e, n );
                if ( message[ i ] != decryptedMessageByte ) {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Sign a message with the private key(n, d) and CRC16
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public UInt32 SignCRC16( byte[] message ) {
            UInt16 crc = CalculateCRC16( message );
            UInt16 lower = (UInt16)ModularExponentiation( (byte)( crc & 0xff ), d, n );
            UInt16 upper = (UInt16)ModularExponentiation( (byte)( crc >> 8 ), d, n );
            return (UInt32)lower | ( (UInt32)upper << 16 );
        }

        /// <summary>
        /// Verify a message with the public key(n, e) and CRC16
        /// </summary>
        /// <param name="message"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public bool VerifyCRC16( byte[] message, UInt32 signature ) {
            UInt16 crc = CalculateCRC16( message );
            bool matchLower = Verify( (byte)(crc & 0xff ), (UInt16)( signature & 0xffff ) );
            bool matchUpper = Verify( (byte)( crc >> 8 ), (UInt16)( signature >> 16 ) );
            return matchLower && matchUpper;
        }

        /// <summary>
        /// Modular exponentiation
        /// </summary>
        /// <param name="baseValue"></param>
        /// <param name="exponent"></param>
        /// <param name="modulus"></param>
        /// <returns></returns>
        private static int ModularExponentiation( UInt16 baseValue, UInt16 exponent, UInt16 modulus ) {
            UInt16 result = 1;
            UInt16 power = (UInt16)( baseValue % modulus );
            while ( exponent > 0 ) {
                if ( ( exponent & 1 ) == 1 ) {
                    result = (UInt16)( ( (UInt32)result * (UInt32)power ) % modulus );
                }
                power = (UInt16)( ( (UInt32)power * (UInt32)power ) % modulus );
                exponent >>= 1;
            }
            return (int)result;
        }

        /// <summary>
        /// Calculate CRC16
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private static UInt16 CalculateCRC16( byte[] data ) {
            UInt16 crc = 0;
            foreach ( byte d in data ) {
                crc ^= d;
                for ( int j = 0 ; j < 8 ; j++ ) {
                    if ( ( crc & 1 ) == 1 ) {
                        crc = (UInt16)( ( crc >> 1 ) ^ 0xA001 );
                    } else {
                        crc = (UInt16)( crc >> 1 );
                    }
                }
            }
            return crc;
        }
    }
}
