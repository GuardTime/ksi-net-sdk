using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using HashAlgorithm = Guardtime.KSI.Hashing.HashAlgorithm;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI PDU.
    /// </summary>
    public abstract class KsiPdu : CompositeTag
    {
        /// <summary>
        ///     Mac TLV type.
        /// </summary>
        protected const uint MacTagType = 0x1f;

        private readonly KsiPduHeader _header;
        private ImprintTag _mac;

        /// <summary>
        ///     Create KSI PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
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

        /// <summary>
        ///     Create KSI PDU from PDU header and data.
        /// </summary>
        /// <param name="header">KSI PDU header</param>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element list</param>
        /// <exception cref="TlvException">thrown when TLV header is null</exception>
        protected KsiPdu(KsiPduHeader header, uint type, bool nonCritical, bool forward, List<TlvTag> value)
            : base(type, nonCritical, forward, value)
        {
            if (header == null)
            {
                throw new TlvException("Invalid TLV header: null.");
            }

            _header = header;
            AddTag(_header);
        }

        /// <summary>
        ///     Get KSI PDU payload.
        /// </summary>
        public abstract KsiPduPayload Payload { get; }

        /// <summary>
        ///     Calculate MAC and attach it to PDU.
        /// </summary>
        /// <param name="key">hmac key</param>
        public void SetMac(byte[] key)
        {
            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(_header);
                writer.WriteTag(Payload);

                ImprintTag mac = new ImprintTag(MacTagType, false, false, CalculateMac(key, stream.ToArray()));
                _mac = PutTag(mac, _mac);
            }
        }

        /// <summary>
        ///     Calculate HMAC for data with given key.
        /// </summary>
        /// <param name="key">hmac key</param>
        /// <param name="data">hmac calculation data</param>
        /// <returns>hmac data hash</returns>
        private static DataHash CalculateMac(byte[] key, byte[] data)
        {
            HMACSHA256 hmac = new HMACSHA256(key);
            return new DataHash(HashAlgorithm.Sha2256, hmac.ComputeHash(data));
        }

        /// <summary>
        ///     Validate mac attached to KSI PDU.
        /// </summary>
        /// <param name="key">message key</param>
        /// <returns>true if MAC is valid</returns>
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

                DataHash hash = CalculateMac(key, stream.ToArray());
                return hash.Equals(_mac.Value);
            }
        }
    }
}