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
    public class AggregationPdu : CompositeTag
    {
        private PduHeader _header;
        private AggregationPduPayload _payload;
        private ImprintTag _mac;

        // TODO: Fix null problem
        public AggregationPduPayload Payload
        {
            get
            {
                return _payload;
            }
        }

        public AggregationPdu(byte[] bytes) : base(bytes)
        {
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        _header = new PduHeader(Value[i]);
                        Value[i] = _header;
                        break;
                    case 0x202:
                        _payload = new AggregationResponse(Value[i]);
                        Value[i] = _payload;
                        break;
                    case 0x203:
                        _payload = new AggregationError(Value[i]);
                        Value[i] = _payload;
                        break;
                    case 0x1f:
                        _mac = new ImprintTag(Value[i]);
                        Value[i] = _mac;
                        break;
                }
            }
        }

        public AggregationPdu(TlvTag tag) : base(tag)
        {
        }

        // TODO: Create correct constructor
        public AggregationPdu() : base(0x200, false, false, new List<TlvTag>())
        {
            _header = new PduHeader();
            Value.Add(_header);

            _payload = new AggregationRequest();
            Value.Add(_payload);

            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(_header);
                writer.WriteTag(_payload);
                _mac = new ImprintTag(0x1F, false, false, new DataHash(HashAlgorithm.Sha2256, CalculateMac(Encoding.UTF8.GetBytes("anon"), ((MemoryStream)writer.BaseStream).ToArray())));
                Value.Add(_mac);
            }
            
        }

        private static byte[] CalculateMac(byte[] key, byte[] data)
        {
            HMACSHA256 hmac = new HMACSHA256(key);
            return hmac.ComputeHash(data);
        }

        protected override void CheckStructure()
        {
            throw new NotImplementedException();
        }
    }
}
