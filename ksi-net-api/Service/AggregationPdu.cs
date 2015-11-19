using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation message PDU.
    /// </summary>
    public sealed class AggregationPdu : KsiPdu
    {
        /// <summary>
        ///     Get PDU payload.
        /// </summary>
        public override KsiPduPayload Payload { get; }

        /// <summary>
        ///     Create aggregation pdu TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        
        public AggregationPdu(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.AggregationPdu.TagType)
            {
                throw new TlvException("Invalid aggregation PDU type(" + Type + ").");
            }

            int headerCount = 0;
            int payloadCount = 0;
            int macCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.AggregationRequestPayload.TagType:
                        Payload = new AggregationRequestPayload(childTag);
                        payloadCount++;
                        break;
                    case Constants.AggregationResponsePayload.TagType:
                        Payload = new AggregationResponsePayload(childTag);
                        payloadCount++;
                        break;
                    case Constants.AggregationErrorPayload.TagType:
                        Payload = new AggregationErrorPayload(childTag);
                        payloadCount++;
                        break;
                    case Constants.KsiPduHeader.TagType:
                        headerCount++;
                        break;
                    case Constants.KsiPdu.MacTagType:
                        macCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (payloadCount != 1)
            {
                throw new TlvException("Only one payload must exist in KSI PDU.");
            }

            if (Payload.Type != Constants.AggregationErrorPayload.TagType && headerCount != 1)
            {
                throw new TlvException("Only one header must exist in KSI PDU.");
            }

            if (Payload.Type != Constants.AggregationErrorPayload.TagType && macCount != 1)
            {
                throw new TlvException("Only one mac must exist in KSI PDU");
            }
        }

        /// <summary>
        ///     Create aggregation pdu TLV element from KSI header and payload.
        /// </summary>
        /// <param name="header">KSI PDU header</param>
        /// <param name="payload">aggregation payload</param>
        /// <param name="mac">pdu message hmac</param>
        
        public AggregationPdu(KsiPduHeader header, KsiPduPayload payload, ImprintTag mac)
            : base(header, mac, Constants.AggregationPdu.TagType, false, false, new ITlvTag[] { header, payload, mac })
        {
            Payload = payload;
        }
    }
}