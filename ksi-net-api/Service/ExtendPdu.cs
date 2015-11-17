using System;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extension PDU.
    /// </summary>
    public sealed class ExtendPdu : KsiPdu
    {
        private readonly ExtendPduPayload _payload;

        /// <summary>
        ///     Create extend PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public ExtendPdu(TlvTag tag) : base(tag)
        {
            if (Type != Constants.ExtendPdu.TagType)
            {
                throw new TlvException("Invalid extend PDU type(" + Type + ").");
            }

            int headerCount = 0;
            int payloadCount = 0;
            int macCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case Constants.ExtendRequestPayload.TagType:
                        _payload = new ExtendRequestPayload(this[i]);
                        payloadCount++;
                        break;
                    case Constants.ExtendResponsePayload.TagType:
                        _payload = new ExtendResponsePayload(this[i]);
                        payloadCount++;
                        break;
                    case Constants.ExtendError.TagType:
                        _payload = new ExtendError(this[i]);
                        payloadCount++;
                        break;
                    case Constants.KsiPduHeader.TagType:
                        headerCount++;
                        break;
                    case Constants.KsiPdu.MacTagType:
                        macCount++;
                        break;
                    default:
                        VerifyUnknownTag(this[i]);
                        break;
                }
            }

            if (payloadCount != 1)
            {
                throw new TlvException("Only one payload must exist in KSI PDU.");
            }

            if (_payload.Type != Constants.ExtendError.TagType && headerCount != 1)
            {
                throw new TlvException("Only one header must exist in KSI PDU.");
            }

            if (_payload.Type != Constants.ExtendError.TagType && macCount != 1)
            {
                throw new TlvException("Only one mac must exist in KSI PDU.");
            }
        }

        /// <summary>
        ///     Create extend pdu from KSI header and extend pdu payload.
        /// </summary>
        /// <param name="header">KSI header</param>
        /// <param name="payload">Extend pdu payload</param>
        /// <exception cref="TlvException">thrown when payload is null</exception>
        public ExtendPdu(KsiPduHeader header, ExtendPduPayload payload, ImprintTag mac)
            : base(header, mac, Constants.ExtendPdu.TagType, false, false, new List<TlvTag>() { header, payload, mac  })
        {
            _payload = payload;
        }

        /// <summary>
        ///     Get extension PDU payload.
        /// </summary>
        public override KsiPduPayload Payload
        {
            get { return _payload; }
        }
    }
}