// skuuzie

using System.Security.Cryptography;
using System.Text;

public enum HashAlgorithm
{
    SHA256,
    SHA512
}

public enum AuthenticatedHashAlgorithm
{
    HMAC_SHA256,
    HMAC_SHA512
}

namespace Kriptos
{
    using KriptosUtil;

    public class KriptosSign
    {
        public KriptosSign(byte[] key, AuthenticatedHashAlgorithm? alg)
        {
            InternalKey = key;
            if (alg != null)
            {
                Algorithm = (AuthenticatedHashAlgorithm)alg;
            }
        }

        internal byte[] InternalKey;
        public AuthenticatedHashAlgorithm Algorithm = AuthenticatedHashAlgorithm.HMAC_SHA512;

        public string SignData(byte[] message)
        {
            return KriptosInner.GenerateHMAC(Algorithm, InternalKey, message).Hex();
        }

        public bool VerifyData(byte[] message, byte[] hashed)
        {
            return KriptosInner.VerifyHMAC(Algorithm, InternalKey, message, hashed);
        }

        public bool VerifyData(byte[] message, string hashed)
        {
            return KriptosInner.VerifyHMAC(Algorithm, InternalKey, message, hashed.Unhex());
        }

        private class KriptosInner
        {
            public static byte[] Hash(HashAlgorithm alg, byte[] data)
            {
                return alg switch
                {
                    HashAlgorithm.SHA256 => SHA256.HashData(data),
                    HashAlgorithm.SHA512 => SHA512.HashData(data),
                    _ => throw new ArgumentException("Unsupported algorithm"),
                };
            }

            public static byte[] GenerateHMAC(AuthenticatedHashAlgorithm alg, byte[] key, byte[] data)
            {
                return alg switch
                {
                    AuthenticatedHashAlgorithm.HMAC_SHA256 => HMACSHA256.HashData(key, data),
                    AuthenticatedHashAlgorithm.HMAC_SHA512 => HMACSHA512.HashData(key, data),
                    _ => throw new ArgumentException("Unsupported algorithm"),
                };
            }

            public static bool VerifyHMAC(AuthenticatedHashAlgorithm alg, byte[] key, byte[] data, byte[] hashed)
            {
                int hSize;
                byte[] _supposedly;

                switch (alg)
                {
                    case AuthenticatedHashAlgorithm.HMAC_SHA256:
                        hSize = HMACSHA256.HashSizeInBytes;
                        if (hashed.Length != hSize) return false;

                        _supposedly = GenerateHMAC(alg, key, data);

                        return General.VerifyBuf(_supposedly, hashed, hSize);

                    case AuthenticatedHashAlgorithm.HMAC_SHA512:
                        hSize = HMACSHA512.HashSizeInBytes;
                        if (hashed.Length != hSize) return false;

                        _supposedly = GenerateHMAC(alg, key, data);

                        return General.VerifyBuf(_supposedly, hashed, hSize);

                    default:
                        return false;
                }
            }
        }
    }
}

namespace KriptosUtil
{
    public static class Extensions
    {
        public static string Hex(this byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", string.Empty);
        }
        public static byte[] Unhex(this string data)
        {
            return Convert.FromHexString(data);
        }
        public static byte[] ToBytes(this string data)
        {
            return Encoding.ASCII.GetBytes(data);
        }
    }

    public static class General
    {
        public static bool VerifyBuf(byte[] b1, byte[] b2, int size)
        {
            if (b1.Length != b2.Length) return false;
            for (int i = 0; i < size; i++)
            {
                if ((b1[i] ^ b2[i]) != 0) return false;
            }
            return true;
        }
    }
}