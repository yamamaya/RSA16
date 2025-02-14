using System.Diagnostics;
using System.Security.Cryptography;

namespace EncryptionExperiments {
    internal class Program {
        static void Main( string[] args ) {
            for ( int j = 0 ; j < 1000 ; j++ ) {
                (UInt16 n, UInt16 e, UInt16 d) = RSA16.GenerateKeys();
                var rsa16 = new RSA16( n, e, d, (byte)( j % 256 ) );
                Console.WriteLine( $"Test #{j} n: {n}, e: {e}, d: {d}" );

                // 0から255までのメッセージを暗号化して復号化
                {
                    for ( int i = 0 ; i <= 255 ; i++ ) {
                        byte message = (byte)i;
                        UInt16 chiper = rsa16.Encrypt( message );
                        byte decrypted = rsa16.Decrypt( chiper );
                        if ( message != decrypted ) {
                            Console.WriteLine( "Mismatch at Test #1" );
                            Console.WriteLine( $"message: {message}, chiper: {chiper:x4}, decrypted: {decrypted}" );
                            Console.ReadKey();
                            break;
                        }
                    }
                }

                // 256バイトのメッセージを暗号化して復号化
                {
                    byte[] message = new byte[ 256 ];
                    for ( int i = 0 ; i < 256 ; i++ ) {
                        message[ i ] = (byte)RandomNumberGenerator.GetInt32( 0, 256 );
                    }
                    byte[] chiper = rsa16.EncryptBytes( message );
                    byte[] decrypted = rsa16.DecryptBytes( chiper );
                    for ( int i = 0 ; i < 256 ; i++ ) {
                        if ( message[ i ] != decrypted[ i ] ) {
                            Console.WriteLine( "Mismatch at Test #2" );
                            Console.WriteLine( $"Message: {message[ i ]}, Decrypted: {decrypted[ i ]}" );
                            Console.ReadKey();
                            break;
                        }
                    }
                }
            }

            Console.ReadKey();
        }
    }
}
