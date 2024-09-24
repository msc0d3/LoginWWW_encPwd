using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static LoginWWW_netframe.Interop.Box.Curve25519XSalsa20Poly1305;

namespace LoginWWW_netframe
{
    public class SealedPublicKeyBox
    {
        public const int RecipientPublicKeyBytes = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
        private const int CryptoBoxSealbytes = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES + crypto_box_curve25519xsalsa20poly1305_MACBYTES;
        public static byte[] Create(string message, byte[] recipientPublicKey)
        {
            return Create(Encoding.UTF8.GetBytes(message), recipientPublicKey);
        }
        public static byte[] Create(byte[] message, byte[] recipientPublicKey)
        {
            //if (recipientPublicKey == null || recipientPublicKey.Length != RecipientPublicKeyBytes)
            //    throw new KeyOutOfRangeException(nameof(recipientPublicKey), recipientPublicKey?.Length ?? 0, $"recipientPublicKey must be {RecipientPublicKeyBytes} bytes in length.");

            var buffer = new byte[message.Length + CryptoBoxSealbytes];

            SodiumCore.Initialize();
            var ret = crypto_box_seal(buffer, message, (ulong)message.Length, recipientPublicKey);

            if (ret != 0)
                throw new CryptographicException("Failed to create SealedBox");

            return buffer;
        }
    }
}
