using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using HashAlgorithm = Guardtime.KSI.Hashing.HashAlgorithm;

namespace Guardtime.KSI.Service
{
    public abstract class KsiPdu : CompositeTag
    {
        // TODO: Better name
        private const uint MacTagType = 0x1f;

        private readonly KsiPduHeader _header;
        private ImprintTag _mac;

        // TODO: Payload can be overridden and is inaccurate when calculatemac is called from constructor
        public abstract KsiPduPayload Payload
        {
            get;
        }

        protected KsiPdu(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case KsiPduHeader.TagType:
                        _header = new KsiPduHeader(this[i]);
                        this[i] = _header;
                        break;
                    case MacTagType:
                        _mac = new ImprintTag(this[i]);
                        this[i] = _mac;
                        break;
                }
            }
        }

        protected KsiPdu(KsiPduHeader header, uint type, bool nonCritical, bool forward, List<TlvTag> value) : base(type, nonCritical, forward, value)
        {
            if (header == null)
            {
                throw new ArgumentNullException("header");
            }

            _header = header;
            AddTag(_header);
        }

        public void CalculateMac(byte[] key)
        {
            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(_header);
                writer.WriteTag(Payload);

                HMACSHA256 hmac = new HMACSHA256(key);
                ImprintTag mac = new ImprintTag(MacTagType, false, false, new DataHash(HashAlgorithm.Sha2256, hmac.ComputeHash(stream.ToArray())));
                _mac = PutTag(mac, _mac);
            }
        }

        public bool ValidateMac(byte[] key)
        {
            if (_mac == null)
            {
                return false;
            }

            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(_header);
                writer.WriteTag(Payload);

                HMACSHA256 hmac = new HMACSHA256(key);
                DataHash hash = new DataHash(HashAlgorithm.Sha2256, hmac.ComputeHash(stream.ToArray()));
                return hash.Equals(_mac.Value);
            }
        }

    }
}
