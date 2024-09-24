using PInvoke;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static PInvoke.BCrypt;

namespace LoginWWW_netframe
{
    public class AESGCM
    {
        public unsafe static byte[] GcmEncrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag, byte[] pbAuthData = null)
        {
            pbAuthData = pbAuthData ?? new byte[0];

            NTSTATUS status = 0;

            using (var provider = BCryptOpenAlgorithmProvider(AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM))
            {
                BCryptSetProperty(provider, PropertyNames.BCRYPT_CHAINING_MODE, ChainingModes.Gcm);

                var tagLengths = BCryptGetProperty<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>(provider, PropertyNames.BCRYPT_AUTH_TAG_LENGTH);

                if (pbTag.Length < tagLengths.dwMinLength
                || pbTag.Length > tagLengths.dwMaxLength
                || (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
                    throw new ArgumentException("Invalid tag length");

                using (var key = BCryptGenerateSymmetricKey(provider, pbKey))
                {
                    var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
                    fixed (byte* pTagBuffer = pbTag)
                    fixed (byte* pNonce = pbNonce)
                    fixed (byte* pAuthData = pbAuthData)
                    {
                        authInfo.pbNonce = pNonce;
                        authInfo.cbNonce = pbNonce.Length;
                        authInfo.pbTag = pTagBuffer;
                        authInfo.cbTag = pbTag.Length;
                        authInfo.pbAuthData = pAuthData;
                        authInfo.cbAuthData = pbAuthData.Length;

                        //Initialize Cipher Text Byte Count
                        int pcbCipherText = pbData.Length;

                        //Allocate Cipher Text Buffer
                        byte[] pbCipherText = new byte[pcbCipherText];

                        fixed (byte* plainText = pbData)
                        fixed (byte* cipherText = pbCipherText)
                        {
                            //Encrypt The Data
                            status = BCryptEncrypt(
                               key,
                               plainText,
                               pbData.Length,
                               &authInfo,
                               null,
                               0,
                               cipherText,
                               pbCipherText.Length,
                               out pcbCipherText,
                               0);
                        }

                        if (status != NTSTATUS.Code.STATUS_SUCCESS)
                            throw new CryptographicException($"BCryptEncrypt failed result {status:X} ");

                        return pbCipherText;

                    }
                }
            }
        }
    }
}
