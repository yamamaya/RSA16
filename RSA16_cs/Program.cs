using System.Diagnostics;
using System.Security.Cryptography;
using OaktreeLab.Utils.Cryptography;

namespace EncryptionExperiments {
    internal class Program {
        static void Main( string[] args ) {

            bool result = true;

            // Test #1: 1000 times durability test. Repeat test #2 - #4 for 1000 times.
            result &= Test1();

            // Test #4: Decrypt a cipher text encrypted by other RSA16 implementation.
            result &= Test4();

            // Test #5: Sign and verify a message with CRC16 signature.
            result &= Test5();

            // Test #6: Verify a CRC16 signature signed by other RSA16 implementation.
            result &= Test6();

            Console.WriteLine();
            Console.WriteLine( "********** All Tests Finished ********" );
            if ( result ) {
                Console.WriteLine();
                Console.WriteLine( "All tests passed." );
            } else {
                Console.WriteLine();
                Console.WriteLine( "Some tests failed." );
            }

            Console.ReadKey();
        }

        private const string SampleMessage = "The quick, brown fox jumps over a lazy dog. DJs flock by when MTV ax quiz prog. Junk MTV quiz graced by fox whelps. Bawds jog, flick quartz, vex nymphs. Waltz, bad nymph, for quick jigs vex! Fox nymphs grab quick-jived waltz. Brick quiz whangs jumpy veldt.";

        /// <summary>
        /// Test #1
        /// </summary>
        /// <remarks>
        /// 1000 times durability test. Repeat test #2 - #4 for 1000 times.
        /// </remarks>
        /// <returns></returns>
        private static bool Test1() {
            // 1000 time durability test
            Console.WriteLine();
            Console.WriteLine( "********** Test #1 **********" );
            Console.WriteLine( "1000 times durability test. Repeat test #2 - #4 for 1000 times." );
            Console.WriteLine();
            for ( int j = 0 ; j < 1000 ; j++ ) {
                (UInt16 n, UInt16 e, UInt16 d) = RSA16.GenerateKeys();
                var rsa16 = new RSA16( n, e, d, (byte)( j % 256 ) );
                Console.Write( $"Test #{j} n: {n}, e: {e}, d: {d} ... " );

                // Test #2: Encription and Decryption of 256 messages
                {
                    for ( int i = 0 ; i <= 255 ; i++ ) {
                        byte message = (byte)i;
                        UInt16 cipher = rsa16.Encrypt( message );
                        byte decrypted = rsa16.Decrypt( cipher );
                        if ( message != decrypted ) {
                            Console.WriteLine( "Mismatch at Test #2" );
                            Console.WriteLine( $"message: {message}, chiper: {cipher:x4}, decrypted: {decrypted}" );
                            return false;
                        }
                    }
                }

                // Test #3: Encryption and Decryption of 256 bytes by CBC mode
                {
                    byte[] message = new byte[ 256 ];
                    for ( int i = 0 ; i < 256 ; i++ ) {
                        message[ i ] = (byte)RandomNumberGenerator.GetInt32( 0, 256 );
                    }
                    byte[] cipher = rsa16.Encrypt( message );
                    byte[] decrypted = rsa16.Decrypt( cipher );
                    for ( int i = 0 ; i < 256 ; i++ ) {
                        if ( message[ i ] != decrypted[ i ] ) {
                            Console.WriteLine( "Mismatch at Test #3" );
                            Console.WriteLine( $"Message: {message[ i ]}, Decrypted: {decrypted[ i ]}" );
                            return false;
                        }
                    }
                }

                // Test #4: Sign and Verify of 256 bytes
                {
                    byte[] message = new byte[ 256 ];
                    for ( int i = 0 ; i < 256 ; i++ ) {
                        message[ i ] = (byte)RandomNumberGenerator.GetInt32( 0, 256 );
                    }
                    byte[] signature = rsa16.Sign( message );
                    bool verified = rsa16.Verify( message, signature );
                    if ( !verified ) {
                        Console.WriteLine( "Mismatch at Test #4" );
                        return false;
                    }
                }

                Console.WriteLine( "Passed" );
            }
            Console.WriteLine();
            Console.WriteLine( "Test #1 all iterations passed" );
            return true;
        }

        /// <summary>
        /// Test #4
        /// </summary>
        /// <remarks>
        /// Decrypt a cipher text encrypted by other RSA16 implementation.
        /// </remarks>
        /// <returns></returns>
        private static bool Test4() {
            Console.WriteLine();
            Console.WriteLine( "********** Test #4 **********" );
            Console.WriteLine( "Decrypt a cipher text encrypted by other RSA16 implementation." );

            // This message was encrypted with the public key (n: 37909, e: 5707) and default IV
            byte[] cipher = new byte[ 512 ] {
                    0x46, 0x00, 0xC7, 0x62, 0x4E, 0x76, 0xAA, 0x92, 0xB8, 0xC1, 0x2D, 0xBB, 0xBA, 0x88, 0x85, 0xE4,
                    0x85, 0xA8, 0xD3, 0x9A, 0xDD, 0x89, 0xE7, 0x96, 0x16, 0xD4, 0xCF, 0xCB, 0xDA, 0xB7, 0x1B, 0xD1,
                    0x92, 0x35, 0xF0, 0x21, 0x8C, 0x2D, 0xDA, 0x70, 0xC3, 0x62, 0x89, 0x28, 0x57, 0x0B, 0xB8, 0x24,
                    0xE6, 0x6C, 0x58, 0x60, 0xAA, 0x92, 0x6D, 0xA8, 0x17, 0xAE, 0xAA, 0xAD, 0xEE, 0xD4, 0x44, 0x86,
                    0x18, 0xEB, 0x78, 0xFB, 0xC2, 0x83, 0xCB, 0x6D, 0xEB, 0x0F, 0xCF, 0x59, 0x20, 0x20, 0xA2, 0x78,
                    0xF9, 0x28, 0xD2, 0xC5, 0xB4, 0xB1, 0x14, 0xF6, 0x94, 0xBD, 0xF9, 0xA4, 0xA6, 0xB9, 0x35, 0xB1,
                    0xA5, 0x91, 0x6B, 0xBB, 0x58, 0xDA, 0x70, 0xCA, 0x43, 0x3A, 0x26, 0x0F, 0xD7, 0x1D, 0x01, 0xF1,
                    0xE4, 0xEE, 0xDE, 0xDB, 0x56, 0xE1, 0x8B, 0xA6, 0x23, 0xAE, 0xE8, 0xD0, 0x82, 0x85, 0x40, 0xC1,
                    0x9F, 0xE6, 0xCA, 0x83, 0x49, 0x30, 0x39, 0x3D, 0x93, 0x24, 0x51, 0x55, 0x38, 0x2B, 0x4B, 0x17,
                    0x3F, 0x63, 0xB6, 0x3C, 0x72, 0x51, 0x11, 0xA2, 0x5B, 0xB9, 0x06, 0xBF, 0x78, 0xE4, 0x35, 0xB1,
                    0x5F, 0xEE, 0x4C, 0x37, 0xD1, 0x42, 0x33, 0x7B, 0xD1, 0x9F, 0xB7, 0xCC, 0x79, 0x01, 0x2C, 0xD2,
                    0x32, 0xC0, 0x36, 0x9F, 0x72, 0xA2, 0x95, 0xB6, 0x29, 0x5A, 0x20, 0x20, 0xC5, 0x02, 0x70, 0x3F,
                    0xDE, 0x4D, 0xD5, 0x17, 0xAD, 0x0D, 0xD2, 0x44, 0x20, 0x20, 0x0D, 0x0B, 0x47, 0x2C, 0x00, 0x04,
                    0x08, 0x47, 0xCB, 0xA1, 0x9E, 0x4B, 0xF5, 0x69, 0x81, 0x59, 0xAA, 0x78, 0x45, 0x41, 0xEB, 0x57,
                    0x53, 0x0F, 0xC5, 0x53, 0xAC, 0x37, 0xB6, 0x3C, 0x45, 0x0E, 0xB4, 0x3E, 0x94, 0x35, 0x76, 0x58,
                    0xC5, 0x07, 0x54, 0x37, 0xB5, 0x42, 0x37, 0x7F, 0x30, 0x2B, 0xF3, 0x0A, 0x58, 0xA8, 0x44, 0x82,
                    0x46, 0x60, 0xDA, 0x6D, 0xC1, 0x06, 0xE9, 0x72, 0xB6, 0x3C, 0x39, 0x6D, 0x49, 0x48, 0x93, 0x53,
                    0x8E, 0x6D, 0x58, 0x34, 0xD8, 0x72, 0xAB, 0x0A, 0x58, 0xA8, 0x80, 0xC9, 0xAA, 0xB8, 0x2B, 0x58,
                    0x20, 0x20, 0x82, 0x1D, 0xAA, 0x3A, 0x62, 0x0F, 0x75, 0x1C, 0x2D, 0x71, 0xAC, 0x21, 0xC9, 0x4B,
                    0x35, 0x55, 0x09, 0x49, 0x87, 0x27, 0x9C, 0x2E, 0x3F, 0x79, 0x2D, 0x36, 0xF3, 0x0A, 0x58, 0xA8,
                    0x77, 0xF3, 0x91, 0x05, 0x64, 0x64, 0x95, 0x82, 0x7B, 0xE8, 0x14, 0x93, 0x6D, 0x90, 0xAD, 0xA3,
                    0x28, 0xAA, 0x0E, 0xC8, 0x1E, 0xA9, 0x99, 0xD0, 0xB0, 0xC5, 0x57, 0xE6, 0x9E, 0xA0, 0x2D, 0xBD,
                    0xDC, 0xD9, 0x31, 0xA7, 0x2E, 0xA3, 0x0A, 0x90, 0x35, 0x84, 0x00, 0xA5, 0x7A, 0xF5, 0x6F, 0xA7,
                    0xC0, 0x9D, 0x4A, 0xEF, 0xDF, 0xDA, 0xC5, 0xC1, 0x81, 0xA4, 0x3C, 0x87, 0x44, 0x86, 0x8E, 0xB6,
                    0xDD, 0x7A, 0x30, 0x64, 0x8F, 0x2A, 0xA8, 0x72, 0xCA, 0x7D, 0x51, 0x50, 0xC5, 0x0F, 0x6A, 0x25,
                    0x85, 0x5D, 0xA2, 0x39, 0xB7, 0x2F, 0xD0, 0x7A, 0x5D, 0x5C, 0x51, 0x58, 0x53, 0x33, 0x1E, 0x18,
                    0xA5, 0x7A, 0xAC, 0x43, 0xCE, 0x17, 0x35, 0x10, 0x47, 0xF3, 0xD4, 0xEA, 0xC7, 0x83, 0x62, 0xE3,
                    0x95, 0x01, 0x64, 0x64, 0x95, 0x82, 0x5A, 0x22, 0x24, 0x11, 0xBC, 0x63, 0x83, 0x8D, 0x81, 0xBD,
                    0x80, 0xC4, 0xF8, 0xAC, 0x28, 0x8D, 0xBD, 0xBA, 0x0F, 0xF1, 0x6B, 0xA3, 0x0A, 0x90, 0x35, 0x84,
                    0x5C, 0x24, 0xC0, 0xD7, 0xEC, 0x9D, 0xD0, 0x76, 0x9F, 0x0C, 0x75, 0x4A, 0xB9, 0xAF, 0x72, 0xFD,
                    0x94, 0xEF, 0xF0, 0xB8, 0x6B, 0xD1, 0xC6, 0xA7, 0x17, 0xE4, 0x7D, 0xB5, 0x20, 0xAD, 0x32, 0xC5,
                    0x6C, 0xFF, 0x33, 0xBC, 0x63, 0xE7, 0xB6, 0xC9, 0x0F, 0xBC, 0xDA, 0xE4, 0xA7, 0xD8, 0xC8, 0xA9
                };

            // Initialize the RSA16 object with the private key (n: 37909, d: 25427) and default IV
            RSA16 rsa16 = new RSA16( 37909, 0, 25427 );
            byte[] decrypted = rsa16.Decrypt( cipher );
            foreach ( byte b in decrypted ) {
                if ( b >= 32 && b <= 126 ) {
                    Console.Write( (char)b );
                } else {
                    Console.Write( '.' );
                }
            }
            Console.WriteLine();
            string decryptedMessage = System.Text.Encoding.ASCII.GetString( decrypted );
            Console.WriteLine();
            if ( decryptedMessage == SampleMessage ) {
                Console.WriteLine( "Test #4 passed" );
            } else {
                Console.WriteLine( "Mismatch at Test #4" );
                return false;
            }
            return true;
        }

        /// <summary>
        /// Test #5
        /// </summary>
        /// <remarks>
        /// Sign and verify a message with CRC16 signature.
        /// </remarks>
        /// <returns></returns>
        private static bool Test5() {
            Console.WriteLine();
            Console.WriteLine( "********** Test #5 **********" );
            Console.WriteLine( "Sign and verify a message with CRC16 signature." );

            // Prepare the message byte array
            byte[] message = SampleMessage.ToCharArray().Select( c => (byte)c ).ToArray();

            // Initialize the RSA16 object with random key
            RSA16 rsa16 = new RSA16();

            // Sign the message
            UInt32 signature = rsa16.SignCRC16( message );

            Console.WriteLine();
            Console.WriteLine( $"Signature: {signature:x8}" );

            // Verify the signature
            bool verified = rsa16.VerifyCRC16( message, signature );

            Console.WriteLine();
            if ( verified ) {
                Console.WriteLine( "Test #5 passed" );
            } else {
                Console.WriteLine( "Mismatch at Test #5" );
                return false;
            }
            return true;
        }

        /// <summary>
        /// Test #6
        /// </summary>
        /// <remarks
        /// Verify a CRC16 signature signed by other RSA16 implementation.
        /// </remarks>
        /// <returns></returns>
        private static bool Test6() {
            Console.WriteLine();
            Console.WriteLine( "********** Test #6 **********" );
            Console.WriteLine( "Verify a CRC16 signature signed by other RSA16 implementation." );

            // This signature was signed by the private key (n: 37909, d: 25427)
            UInt32 signature = 0x34823CC5;

            // Prepare the message byte array
            byte[] message = SampleMessage.ToCharArray().Select( c => (byte)c ).ToArray();

            // Initialize the RSA16 object with the public key (n: 37909, e: 5707)
            RSA16 rsa16 = new RSA16( 37909, 5707, 0 );

            // Verify the signature
            bool verified = rsa16.VerifyCRC16( message, signature );

            Console.WriteLine();
            if ( verified ) {
                Console.WriteLine( "Test #6 passed" );
            } else {
                Console.WriteLine( "Mismatch at Test #6" );
                return false;
            }
            return true;
        }
    }
}
