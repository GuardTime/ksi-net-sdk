using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation message PDU.
    /// </summary>
    public sealed class AggregationPdu : KsiPdu
    {
        private readonly AggregationPduPayload _payload;

        /// <summary>
        ///     Create aggregation pdu TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public AggregationPdu(TlvTag tag) : base(tag)
        {
            if (Type != Constants.AggregationPdu.TagType)
            {
                throw new TlvException("Invalid aggregation PDU type(" + Type + ").");
            }

            int headerCount = 0;
            int payloadCount = 0;
            int macCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case Constants.AggregationRequestPayload.TagType:
                        _payload = new AggregationRequestPayload(this[i]);
                        payloadCount++;
                        break;
                    case Constants.AggregationResponsePayload.TagType:
                        _payload = new AggregationResponsePayload(this[i]);
                        payloadCount++;
                        break;
                    case Constants.AggregationError.TagType:
                        _payload = new AggregationError(this[i]);
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

            if (_payload.Type != Constants.AggregationError.TagType && headerCount != 1)
            {
                throw new TlvException("Only one header must exist in KSI PDU.");
            }

            if (_payload.Type != Constants.AggregationError.TagType && macCount != 1)
            {
                throw new TlvException("Only one mac must exist in KSI PDU");
            }
        }

        /// <summary>
        ///     Create aggregation pdu TLV element from KSI header and payload.
        /// </summary>
        /// <param name="header">KSI PDU header</param>
        /// <param name="payload">aggregation payload</param>
        /// <exception cref="TlvException">thrown when payload is null</exception>
        public AggregationPdu(KsiPduHeader header, AggregationPduPayload payload, ImprintTag mac)
            : base(header, mac, Constants.AggregationPdu.TagType, false, false, new List<TlvTag>() { header, payload, mac })
        {
            _payload = payload;
        }

        /// <summary>
        ///     Get aggregation message payload.
        /// </summary>
        public override KsiPduPayload Payload
        {
            get { return _payload; }
        }
    }
}