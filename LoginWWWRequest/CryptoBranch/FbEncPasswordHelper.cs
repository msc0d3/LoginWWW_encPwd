using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LoginWWWRequest.CryptoBranch.AESBranch;
using LoginWWWRequest.CryptoBranch.LibsodiumBranch;

namespace LoginWWWRequest.CryptoBranch
{
    public static class FbEncPasswordHelper
    {
        public static string GenerateEncPassword(string password, string publicKey, string keyId, string version)
        {
            var time = DateTime.UtcNow.ToTimestamp();
            var keyBytes = publicKey.HexToBytes();
            var key = new byte[32];
            new Random().NextBytes(key);
            var iv = new byte[12];
            var tag = new byte[16];
            var plainText = Encoding.UTF8.GetBytes(password);
            //var cipherText = new byte[plainText.Length];

            //var cipherText = EncryptWithAesGcm(plainText, key, iv, tag, Encoding.UTF8.GetBytes(time.ToString()));
            var cipherText = AESGCM.GcmEncrypt(pbData: plainText, pbKey: key, pbNonce: iv, pbTag: tag, pbAuthData: Encoding.UTF8.GetBytes(time.ToString()));

            var encryptedKey = SealedPublicKeyBox.Create(key, keyBytes);
            var bytesOfLen = BitConverter.GetBytes((short)encryptedKey.Length);
            var info = new byte[] { 1, byte.Parse(keyId) };
            var bytes = info.Concat(bytesOfLen).Concat(encryptedKey).Concat(tag).Concat(cipherText);

            var str = $"#PWD_BROWSER:{version}:{time}:{Convert.ToBase64String(bytes)}";
            return str;
        }
        private static byte[] HexToBytes(this string hex)
        {
            return Enumerable.Range(0, hex.Length / 2)
                .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))
                .ToArray();
        }
        private static T[] Concat<T>(this T[] x, T[] y)
        {
            var z = new T[x.Length + y.Length];
            x.CopyTo(z, 0);
            y.CopyTo(z, x.Length);
            return z;
        }
        private static readonly DateTime _jan1St1970 = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private static long ToTimestamp(this DateTime d)
        {
            return (long)(d.ToUniversalTime() - _jan1St1970).TotalSeconds;
        }
    }
}
