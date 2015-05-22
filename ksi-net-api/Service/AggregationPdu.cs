using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using HashAlgorithm = Guardtime.KSI.Hashing.HashAlgorithm;

namespace Guardtime.KSI.Service
{
    class AggregationPdu : CompositeTag
    {
        private PduHeader _header;
        private AggregationPduPayload _payload;
        private ImprintTag _mac;

        public AggregationPdu(TlvTag tag) : base(tag)
        {
        }

        // Create correct constructor
        public AggregationPdu() : base(0x200, false, false)
        {
            _header = new PduHeader();
            Value.Add(_header);

            _payload = new AggregationRequest();
            Value.Add(_payload);

            using (var writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(_header);
                writer.WriteTag(_payload);
                _mac = new ImprintTag(0x1F, false, false, new DataHash(HashAlgorithm.Sha2256, CalculateMac(Encoding.UTF8.GetBytes("anon"), ((MemoryStream)writer.BaseStream).ToArray())));
                Value.Add(_mac);
            }
            
        }

        private static byte[] CalculateMac(byte[] key, byte[] data)
        {
            var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(data);
        }

    public override bool IsValidStructure()
        {
            throw new NotImplementedException();
        }
    }
}
