using System;
using System.Security.Cryptography;

namespace Guardtime.KSI.Hashing
{
    public class HmacHasher : IHmacHasher
    {
        public DataHash GetHash(byte[] key, byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            HMACSHA256 hMac = new HMACSHA256(key);
            return new DataHash(HashAlgorithm.Sha2256, hMac.ComputeHash(data));
        }
    }
}