using System;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Service
{
    public sealed class AggregationResponsePayload : AggregationPduPayload
    {
        // Better name
        public const uint TagType = 0x202;
        private const uint RequestIdTagType = 0x1;
        private const uint ConfigTagType = 0x10;
        private const uint RequestAcknowledgmentTagType = 0x11;

        private readonly IntegerTag _requestId;
        private readonly IntegerTag _status;
        private readonly StringTag _errorMessage;

        // TODO: Create config
        private readonly RawTag _config;
        // TODO: Create request acknowledgement 
        private readonly RawTag _requestAcknowledgment;

        public AggregationResponsePayload(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid aggregation response payload type: " + Type);
            }

            int requestIdCount = 0;
            int statusCount = 1;
            int errorMessageCount = 0;
            int configCount = 0;
            int requestAcknowledgmentCount = 0;
            
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case RequestIdTagType:
                        _requestId = new IntegerTag(this[i]);
                        this[i] = _requestId;
                        requestIdCount++;
                        break;
                    case StatusTagType:
                        // TODO: Status should be there but it is not
                        _status = new IntegerTag(this[i]);
                        this[i] = _status;
                        statusCount++;
                        break;
                    case ErrorMessageTagType:
                        _errorMessage = new StringTag(this[i]);
                        this[i] = _errorMessage;
                        errorMessageCount++;
                        break;
                    case ConfigTagType:
                        _config = new RawTag(this[i]);
                        this[i] = _config;
                        configCount++;
                        break;
                    case RequestAcknowledgmentTagType:
                        _requestAcknowledgment = new RawTag(this[i]);
                        this[i] = _requestAcknowledgment;
                        requestAcknowledgmentCount++;
                        break;
                    //TODO: ??
                    case AggregationHashChain.TagType:
                    case CalendarHashChain.TagType:
                    case PublicationRecord.TagTypeSignature:
                    case AggregationAuthenticationRecord.TagType:
                    case CalendarAuthenticationRecord.TagType:
                        break;
                    default:
                        VerifyCriticalTag(this[i]);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new InvalidTlvStructureException("Only one request id must exist in aggregation response payload");
            }

            if (statusCount != 1)
            {
                throw new InvalidTlvStructureException("Only one status code must exist in aggregation response payload");
            }

            if (errorMessageCount > 1)
            {
                throw new InvalidTlvStructureException("Only one error message is allowed in aggregation response payload");
            }

            if (configCount > 1)
            {
                throw new InvalidTlvStructureException("Only one config is allowed in aggregation response payload");
            }

            if (requestAcknowledgmentCount > 1)
            {
                throw new InvalidTlvStructureException("Only one request acknowledgment is allowed in aggregation response payload");
            }
        }

    }
}
