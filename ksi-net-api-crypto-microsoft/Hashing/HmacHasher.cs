using System;
using System.Security.Cryptography;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    /// HMAC hasher
    /// </summary>
    public class HmacHasher : IHmacHasher
    {
        /// <summary>
        ///     Calculate HMAC for data with given key.
        /// </summary>
        /// <param name="key">HMAC key</param>
        /// <param name="data">HMAC calculation data</param>
        /// <returns>HMAC data hash</returns>
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