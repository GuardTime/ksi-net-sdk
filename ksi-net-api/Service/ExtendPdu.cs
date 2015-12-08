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
        /// <summary>
        ///     Get PDU payload.
        /// </summary>
        public override KsiPduPayload Payload { get; }

        /// <summary>
        ///     Create extend PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        
        public ExtendPdu(ITlvTag tag) : base(tag)
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
                        Payload = new ExtendRequestPayload(this[i]);
                        payloadCount++;
                        break;
                    case Constants.ExtendResponsePayload.TagType:
                        Payload = new ExtendResponsePayload(this[i]);
                        payloadCount++;
                        break;
                    case Constants.ExtendErrorPayload.TagType:
                        Payload = new ExtendErrorPayload(this[i]);
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

            if (Payload.Type != Constants.ExtendErrorPayload.TagType && headerCount != 1)
            {
                throw new TlvException("Only one header must exist in KSI PDU.");
            }

            if (Payload.Type != Constants.ExtendErrorPayload.TagType && macCount != 1)
            {
                throw new TlvException("Only one mac must exist in KSI PDU.");
            }
        }

        /// <summary>
        ///     Create extend pdu from KSI header and extend pdu payload.
        /// </summary>
        /// <param name="header">KSI header</param>
        /// <param name="payload">Extend pdu payload</param>
        /// <param name="mac">Extend pdu hmac</param>
        
        public ExtendPdu(KsiPduHeader header, KsiPduPayload payload, ImprintTag mac)
            : base(header, mac, Constants.ExtendPdu.TagType, false, false, new List<ITlvTag>() {header, payload, mac})
        {
            Payload = payload;
        }
    }
}