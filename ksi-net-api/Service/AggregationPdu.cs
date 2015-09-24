using System;
using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Aggregation message PDU.
    /// </summary>
    public sealed class AggregationPdu : KsiPdu
    {
        /// <summary>
        /// Aggregation PDU TLV type.
        /// </summary>
        public const uint TagType = 0x200;

        private readonly AggregationPduPayload _payload;

        /// <summary>
        /// Get aggregation message payload.
        /// </summary>
        public override KsiPduPayload Payload
        {
            get
            {
                return _payload;
            }
        }

        /// <summary>
        /// Create aggregation pdu TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public AggregationPdu(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid aggregation pdu type: " + Type);
            }

            int headerCount = 0;
            int payloadCount = 0;
            int macCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case AggregationRequestPayload.TagType:
                        _payload = new AggregationRequestPayload(this[i]);
                        this[i] = _payload;
                        payloadCount++;
                        break;
                    case AggregationResponsePayload.TagType:
                        _payload = new AggregationResponsePayload(this[i]);
                        this[i] = _payload;
                        payloadCount++;
                        break;
                    case AggregationError.TagType:
                        _payload = new AggregationError(this[i]);
                        this[i] = _payload;
                        payloadCount++;
                        break;

                    // TODO: How to handle parent class types
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

            if (_payload.Type != AggregationError.TagType && headerCount != 1)
            {
                throw new InvalidTlvStructureException("Only one header must exist in ksi pdu");
            }

            if (_payload.Type != AggregationError.TagType && macCount != 1)
            {
                throw new InvalidTlvStructureException("Only one mac must exist in ksi pdu");
            }
        }

        /// <summary>
        /// Create aggregation pdu TLV element from KSI header and payload.
        /// </summary>
        /// <param name="header">KSI PDU header</param>
        /// <param name="payload">aggregation payload</param>
        public AggregationPdu(KsiPduHeader header, AggregationPduPayload payload) : base(header, TagType, false, false, new List<TlvTag>())
        {
            if (payload == null)
            {
                throw new ArgumentNullException("payload");
            }

            _payload = AddTag(payload);
        }
    }
}
