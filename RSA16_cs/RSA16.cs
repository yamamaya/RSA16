using System;
using System.Security.Cryptography;

namespace EncryptionExperiments {
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
            this.IV_enc = 0;
            this.IV_dec = 0;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <remarks>
        /// Initializes an RSA encryptor with the specified keys (n, e, d).
        /// </remarks>
        /// <param name="n"></param>
        /// <param name="e"></param>
        /// <param name="d"></param>
        public RSA16( UInt16 n, UInt16 e, UInt16 d ) : this( n, e, d, 0 ) {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <remarks>
        /// Initializes an RSA encryptor with the specified keys (n, e, d) and the specified CBC mode initialization vector.
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
            ResetIV( 0 );
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
        /// <returns></returns>
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
        /// Encrypt a message
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
        /// Decrypt a cipher
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
        /// Encrypt a byte array
        /// </summary>
        /// <remarks>
        /// CBC mode encryption is performed.
        /// The initialization vector is updated each time.
        /// CBC has its own implementation.
        /// </remarks>
        /// <param name="message"></param>
        /// <returns></returns>
        public byte[] EncryptBytes( byte[] message ) {
            int nChars = message.Length;
            byte c_prev = IV_enc;
            byte[] cipher = new byte[ nChars * 2 ];
            int p = 0;
            for ( int i = 0 ; i < nChars ; i++ ) {
                // Encrypt the message
                UInt16 c = (UInt16)ModularExponentiation( message[ i ], e, n );
                // Store lower byte first
                cipher[ p ] = (byte)( c & 0xff );
                cipher[ p ] ^= c_prev;
                c_prev = cipher[ p ];
                p++;
                // Store higher byte next
                cipher[ p ] = (byte)( c >> 8 );
                cipher[ p ] ^= c_prev;
                c_prev = cipher[ p ];
                p++;
            }
            // Update the initialization vector for the next block
            IV_enc = c_prev;
            return cipher;
        }

        /// <summary>
        /// Decrypt a byte array
        /// </summary>
        /// <remarks>
        /// CBC mode decryption is performed.
        /// The initialization vector is updated each time.
        /// CBC has its own implementation.
        /// </remarks>
        /// <param name="cipher"></param>
        /// <returns></returns>
        public byte[] DecryptBytes( byte[] cipher ) {
            int nChars = cipher.Length / 2;
            byte[] message = new byte[ nChars ];
            byte c_prev = IV_dec;
            int p = 0;
            for ( int i = 0 ; i < nChars ; i++ ) {
                // Retrieve lower byte first
                byte cl = (byte)( cipher[ p ] ^ c_prev );
                c_prev = cipher[ p ];
                p++;
                // Retrieve higher byte next
                byte ch = (byte)( cipher[ p ] ^ c_prev );
                c_prev = cipher[ p ];
                p++;
                // Combine the two bytes
                UInt16 c = (UInt16)( cl | ( ch << 8 ) );
                // Decrypt the message
                message[ i ] = (byte)ModularExponentiation( c, d, n );
            }
            // Update the initialization vector for the next block
            IV_dec = c_prev;
            return message;
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
    }
}
