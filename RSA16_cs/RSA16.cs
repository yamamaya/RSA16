using System;
using System.Security.Cryptography;

namespace EncryptionExperiments {
    /// <summary>
    /// 16ビットRSA暗号化器
    /// </summary>
    class RSA16 {
        /// <summary>
        /// コンストラクタ
        /// </summary>
        /// <remarks>
        /// ランダムな16ビットRSA鍵を生成してRSA暗号化器を生成します。
        /// </remarks>
        /// <exception cref="Exception"></exception>
        public RSA16() {
            (n, e, d) = GenerateKeys();
            this.IV_enc = 0;
            this.IV_dec = 0;
        }

        /// <summary>
        /// コンストラクタ
        /// </summary>
        /// <remarks>
        /// n, e, dを指定してRSA暗号化器を生成します。
        /// </remarks>
        /// <param name="n"></param>
        /// <param name="e"></param>
        /// <param name="d"></param>
        public RSA16( UInt16 n, UInt16 e, UInt16 d ) : this( n, e, d, 0 ) {
        }

        /// <summary>
        /// コンストラクタ
        /// </summary>
        /// <remarks>
        /// n, e, d, ivを指定してRSA暗号化器を生成します。
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
        /// CBCモードの初期化ベクトルのリセット
        /// </summary>
        public void ResetIV() {
            ResetIV( 0 );
        }

        /// <summary>
        /// CBCモードの初期化ベクトルのリセット
        /// </summary>
        /// <param name="iv"></param>
        public void ResetIV( byte iv ) {
            IV_enc = iv;
            IV_dec = iv;
        }

        /// <summary>
        /// モジュラス
        /// </summary>
        private readonly UInt16 n;

        /// <summary>
        /// 公開指数
        /// </summary>
        private readonly UInt16 e;

        /// <summary>
        /// 秘密指数
        /// </summary>
        private readonly UInt16 d;

        /// <summary>
        /// 公開鍵(n, e)
        /// </summary>
        public (UInt16, UInt16) PublicKey => (n, e);

        /// <summary>
        /// 秘密鍵(n, d)
        /// </summary>
        public (UInt16, UInt16) PrivateKey => (n, d);

        /// <summary>
        /// 公開鍵と秘密鍵のセット(n, e, d)
        /// </summary>
        public (UInt16, UInt16, UInt16) Key => (n, e, d);

        /// <summary>
        /// CBCモードの暗号化用の初期化ベクトル
        /// </summary>
        private byte IV_enc = 0;

        /// <summary>
        /// CBCモードの復号化用の初期化ベクトル
        /// </summary>
        private byte IV_dec = 0;

        #region Functions for key generation

        /// <summary>
        /// 鍵の生成
        /// </summary>
        /// <returns></returns>
        public static (UInt16 n, UInt16 e, UInt16 d) GenerateKeys() {
            UInt16 n, e, d;
            // ランダムな16ビットRSA鍵の生成
            UInt16 p, q;
            do {
                p = GenerateRandomPrime( 16, 256 );
                do {
                    q = GenerateRandomPrime( 16, 256 );
                } while ( p == q ); // pとqが異なることを保証
                n = (UInt16)( p * q );
            } while ( n < 256 );

            int phi_n = ( p - 1 ) * ( q - 1 );

            // 公開鍵eの選定
            e = GenerateRandomE( phi_n );

            // 秘密鍵dの計算
            d = (UInt16)ModularInverse( e, phi_n );

            return (n, e, d);
        }

        /// <summary>
        /// ランダムな素数の生成
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
        /// 素数判定
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
        /// 公開鍵eの生成
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
        /// 逆元計算
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
        /// 拡張ユークリッドの互除法
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

        /// <inheritdoc/>
        public UInt16 Encrypt( byte message ) {
            return (UInt16)ModularExponentiation( message, e, n );
            //// 原初的な実装
            //int c = 1;
            //for ( int i = 0 ; i < e ; i++ ) {
            //    c = ( c * message ) % n;
            //}
            //return (UInt16)c;
        }

        /// <inheritdoc/>
        public byte Decrypt( UInt16 cipher ) {
            return (byte)ModularExponentiation( cipher, d, n );
            //// 原初的な実装
            //int m = 1;
            //int c = (int)cipher;
            //for ( int i = 0 ; i < d ; i++ ) {
            //    m = ( m * c ) % n;
            //}
            //return (byte)m;
        }

        /// <summary>
        /// バイト配列の暗号化
        /// </summary>
        /// <remarks>
        /// CBCモードでの暗号化を行います。
        /// 初期化ベクトルは都度更新されます。
        /// CBCは独自の実装を行っています。
        /// </remarks>
        /// <param name="message"></param>
        /// <returns></returns>
        public byte[] EncryptBytes( byte[] message ) {
            int nChars = message.Length;
            byte c_prev = IV_enc;
            byte[] cipher = new byte[ nChars * 2 ];
            int p = 0;
            for ( int i = 0 ; i < nChars ; i++ ) {
                UInt16 c = (UInt16)ModularExponentiation( message[ i ], e, n );
                cipher[ p ] = (byte)( c & 0xff );
                cipher[ p ] ^= c_prev;
                c_prev = cipher[ p ];
                p++;
                cipher[ p ] = (byte)( c >> 8 );
                cipher[ p ] ^= c_prev;
                c_prev = cipher[ p ];
                p++;
            }
            IV_enc = c_prev;
            return cipher;
        }

        /// <summary>
        /// バイト配列の復号化
        /// </summary>
        /// <remarks>
        /// CBCモードでの復号化を行います。
        /// 初期化ベクトルは都度更新されます。
        /// CBCは独自の実装を行っています。
        /// </remarks>
        /// <param name="cipher"></param>
        /// <returns></returns>
        public byte[] DecryptBytes( byte[] cipher ) {
            int nChars = cipher.Length / 2;
            byte[] message = new byte[ nChars ];
            byte c_prev = IV_dec;
            int p = 0;
            for ( int i = 0 ; i < nChars ; i++ ) {
                byte c_curr = cipher[ p ];
                cipher[ p ] ^= c_prev;
                byte cl = cipher[ p ];
                c_prev = c_curr;
                p++;
                c_curr = cipher[ p ];
                cipher[ p ] ^= c_prev;
                byte ch = cipher[ p ];
                c_prev = c_curr;
                p++;
                UInt16 c = (UInt16)( cl | ( ch << 8 ) );
                message[ i ] = (byte)ModularExponentiation( c, d, n );
            }
            IV_dec = c_prev;
            return message;
        }

        /// <summary>
        /// べき乗剰余計算
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
