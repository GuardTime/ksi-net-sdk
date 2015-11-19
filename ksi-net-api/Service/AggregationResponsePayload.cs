using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation response payload.
    /// </summary>
    public sealed class AggregationResponsePayload : KsiPduPayload
    {
        // TODO: Create config
        private readonly RawTag _config;
        private readonly StringTag _errorMessage;
        // TODO: Create request acknowledgement 
        private readonly RawTag _requestAcknowledgment;
        private readonly IntegerTag _requestId;
        private readonly IntegerTag _status;

        /// <summary>
        ///     Create aggregation response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public AggregationResponsePayload(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.AggregationResponsePayload.TagType)
            {
                throw new TlvException("Invalid aggregation response payload type(" + Type + ").");
            }

            int requestIdCount = 0;
            int statusCount = 0;
            int errorMessageCount = 0;
            int configCount = 0;
            int requestAcknowledgmentCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.AggregationResponsePayload.RequestIdTagType:
                        _requestId = new IntegerTag(childTag);
                        requestIdCount++;
                        break;
                    case Constants.KsiPduPayload.StatusTagType:
                        _status = new IntegerTag(childTag);
                        statusCount++;
                        break;
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        _errorMessage = new StringTag(childTag);
                        errorMessageCount++;
                        break;
                    case Constants.AggregationResponsePayload.ConfigTagType:
                        _config = new RawTag(childTag);
                        configCount++;
                        break;
                    case Constants.AggregationResponsePayload.RequestAcknowledgmentTagType:
                        _requestAcknowledgment = new RawTag(childTag);
                        requestAcknowledgmentCount++;
                        break;
                    case Constants.AggregationHashChain.TagType:
                    case Constants.CalendarHashChain.TagType:
                    case Constants.PublicationRecord.TagTypeSignature:
                    case Constants.AggregationAuthenticationRecord.TagType:
                    case Constants.CalendarAuthenticationRecord.TagType:
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new TlvException("Only one request id must exist in aggregation response payload.");
            }

            // TODO: Should be mandatory element, but server side is broken.
            if (statusCount > 1)
            {
                throw new TlvException("Only one status code must exist in aggregation response payload.");
            }

            if (errorMessageCount > 1)
            {
                throw new TlvException(
                    "Only one error message is allowed in aggregation response payload.");
            }

            if (configCount > 1)
            {
                throw new TlvException("Only one config is allowed in aggregation response payload.");
            }

            if (requestAcknowledgmentCount > 1)
            {
                throw new TlvException(
                    "Only one request acknowledgment is allowed in aggregation response payload.");
            }
        }

        /// <summary>
        ///     Get error message if it exists.
        /// </summary>
        public string ErrorMessage => _errorMessage?.Value;

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId => _requestId.Value;

        /// <summary>
        ///     Get status code.
        /// </summary>
        public ulong Status => _status?.Value ?? 0;
    }
}