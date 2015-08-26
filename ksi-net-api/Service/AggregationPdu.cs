using System;
using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Service
{
    public sealed class AggregationPdu : KsiPdu
    {
        // TODO: Better name
        public const uint TagType = 0x200;

        private readonly AggregationPduPayload _payload;

        public override KsiPduPayload Payload
        {
            get
            {
                return _payload;
            }
        }

        public AggregationPdu(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid aggregation pdu type: " + Type);
            }

            int payloadCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
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
                    case MacTagType:
                        break;
                    default:
                        VerifyCriticalTag(this[i]);
                        break;
                }
            }

            if (payloadCount != 1)
            {
                throw new InvalidTlvStructureException("Only one payload must exist in ksi pdu");
            }
        }

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
