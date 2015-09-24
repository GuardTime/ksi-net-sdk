using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Extension PDU.
    /// </summary>
    public sealed class ExtendPdu : KsiPdu
    {
        /// <summary>
        /// Extension PDU TLV type.
        /// </summary>
        public const uint TagType = 0x300;

        private readonly ExtendPduPayload _payload;

        /// <summary>
        /// Get extension PDU payload.
        /// </summary>
        public override KsiPduPayload Payload
        {
            get
            {
                return _payload;
            }
        }

        /// <summary>
        /// Create extend PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtendPdu(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid extend pdu type: " + Type);
            }

            int headerCount = 0;
            int payloadCount = 0;
            int macCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case ExtendRequestPayload.TagType:
                        _payload = new ExtendRequestPayload(this[i]);
                        this[i] = _payload;
                        payloadCount++;
                        break;
                    case ExtendResponsePayload.TagType:
                        _payload = new ExtendResponsePayload(this[i]);
                        this[i] = _payload;
                        payloadCount++;
                        break;
                    case ExtendError.TagType:
                        _payload = new ExtendError(this[i]);
                        this[i] = _payload;
                        payloadCount++;
                        break;
                    case KsiPduHeader.TagType:
                        headerCount++;
                        break;
                    case MacTagType:
                        macCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (payloadCount != 1)
            {
                throw new InvalidTlvStructureException("Only one payload must exist in ksi pdu");
            }

            if (_payload.Type != ExtendError.TagType && headerCount != 1)
            {
                throw new InvalidTlvStructureException("Only one header must exist in ksi pdu");
            }

            if (_payload.Type != ExtendError.TagType && macCount != 1)
            {
                throw new InvalidTlvStructureException("Only one mac must exist in ksi pdu");
            }
        }

        /// <summary>
        /// Create extend pdu from KSI header and extend pdu payload.
        /// </summary>
        /// <param name="header">KSI header</param>
        /// <param name="payload">Extend pdu payload</param>
        public ExtendPdu(KsiPduHeader header, ExtendPduPayload payload) : base(header, TagType, false, false, new List<TlvTag>())
        {
            if (payload == null)
            {
                throw new ArgumentNullException("payload");
            }

            _payload = AddTag(payload);
        }

    }
}