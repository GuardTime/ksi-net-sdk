using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation response payload.
    /// </summary>
    public sealed class AggregationResponsePayload : AggregationPduPayload
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
        public AggregationResponsePayload(TlvTag tag) : base(tag)
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

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case Constants.AggregationResponsePayload.RequestIdTagType:
                        _requestId = new IntegerTag(this[i]);
                        requestIdCount++;
                        break;
                    case Constants.KsiPduPayload.StatusTagType:
                        _status = new IntegerTag(this[i]);
                        statusCount++;
                        break;
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        _errorMessage = new StringTag(this[i]);
                        errorMessageCount++;
                        break;
                    case Constants.AggregationResponsePayload.ConfigTagType:
                        _config = new RawTag(this[i]);
                        configCount++;
                        break;
                    case Constants.AggregationResponsePayload.RequestAcknowledgmentTagType:
                        _requestAcknowledgment = new RawTag(this[i]);
                        requestAcknowledgmentCount++;
                        break;
                    case Constants.AggregationHashChain.TagType:
                    case Constants.CalendarHashChain.TagType:
                    case Constants.PublicationRecord.TagTypeSignature:
                    case Constants.AggregationAuthenticationRecord.TagType:
                    case Constants.CalendarAuthenticationRecord.TagType:
                        break;
                    default:
                        VerifyUnknownTag(this[i]);
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
        public string ErrorMessage
        {
            get { return _errorMessage == null ? null : _errorMessage.Value; }
        }

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId
        {
            get { return _requestId.Value; }
        }

        /// <summary>
        ///     Get status code.
        /// </summary>
        public ulong Status
        {
            get { return _status == null ? 0 : _status.Value; }
        }
    }
}