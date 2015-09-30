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
        /// <summary>
        ///     Aggregation response payload TLV type.
        /// </summary>
        public const uint TagType = 0x202;

        private const uint RequestIdTagType = 0x1;
        private const uint ConfigTagType = 0x10;
        private const uint RequestAcknowledgmentTagType = 0x11;

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
            if (Type != TagType)
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
                    case RequestIdTagType:
                        _requestId = new IntegerTag(this[i]);
                        this[i] = _requestId;
                        requestIdCount++;
                        break;
                    case StatusTagType:
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
                    case AggregationHashChain.TagType:
                    case CalendarHashChain.TagType:
                    case PublicationRecord.TagTypeSignature:
                    case AggregationAuthenticationRecord.TagType:
                    case CalendarAuthenticationRecord.TagType:
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
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