using System;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

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

            HMac hMac = new HMac(new Sha256Digest());
            hMac.Init(new KeyParameter(key));
            hMac.BlockUpdate(data, 0, data.Length);

            byte[] value = new byte[HashAlgorithm.Sha2256.Length];
            hMac.DoFinal(value, 0);
            return new DataHash(HashAlgorithm.Sha2256, value);
        }
    }
}