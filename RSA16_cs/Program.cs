using System.Diagnostics;
using System.Security.Cryptography;
using OaktreeLab.Utils.Cryptography;

namespace EncryptionExperiments {
    internal class Program {
        static void Main( string[] args ) {
            for ( int j = 0 ; j < 1000 ; j++ ) {
                (UInt16 n, UInt16 e, UInt16 d) = RSA16.GenerateKeys();
                var rsa16 = new RSA16( n, e, d, (byte)( j % 256 ) );
                Console.WriteLine( $"Test #{j} n: {n}, e: {e}, d: {d}" );

                // Encription and Decryption of 256 messages
                {
                    for ( int i = 0 ; i <= 255 ; i++ ) {
                        byte message = (byte)i;
                        UInt16 cipher = rsa16.Encrypt( message );
                        byte decrypted = rsa16.Decrypt( cipher );
                        if ( message != decrypted ) {
                            Console.WriteLine( "Mismatch at Test #1" );
                            Console.WriteLine( $"message: {message}, chiper: {cipher:x4}, decrypted: {decrypted}" );
                            Console.ReadKey();
                            break;
                        }
                    }
                }

                // Encryption and Decryption of 256 bytes
                {
                    byte[] message = new byte[ 256 ];
                    for ( int i = 0 ; i < 256 ; i++ ) {
                        message[ i ] = (byte)RandomNumberGenerator.GetInt32( 0, 256 );
                    }
                    byte[] cipher = rsa16.Encrypt( message );
                    byte[] decrypted = rsa16.Decrypt( cipher );
                    for ( int i = 0 ; i < 256 ; i++ ) {
                        if ( message[ i ] != decrypted[ i ] ) {
                            Console.WriteLine( "Mismatch at Test #2" );
                            Console.WriteLine( $"Message: {message[ i ]}, Decrypted: {decrypted[ i ]}" );
                            Console.ReadKey();
                            break;
                        }
                    }
                }

                // Sign and Verify of 256 bytes
                {
                    byte[] message = new byte[ 256 ];
                    for ( int i = 0 ; i < 256 ; i++ ) {
                        message[ i ] = (byte)RandomNumberGenerator.GetInt32( 0, 256 );
                    }
                    byte[] signature = rsa16.Sign( message );
                    bool verified = rsa16.Verify( message, signature );
                    if ( !verified ) {
                        Console.WriteLine( "Mismatch at Test #3" );
                        Console.ReadKey();
                        break;
                    }
                }
            }

            Console.ReadKey();
        }
    }
}
