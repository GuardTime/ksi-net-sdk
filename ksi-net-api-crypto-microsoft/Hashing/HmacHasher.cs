using System;
using System.Security.Cryptography;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    /// Hmac hasher
    /// </summary>
    public class HmacHasher : IHmacHasher
    {
        /// <summary>
        ///     Calculate HMAC for data with given key.
        /// </summary>
        /// <param name="key">hmac key</param>
        /// <param name="data">hmac calculation data</param>
        /// <returns>hmac data hash</returns>
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