using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extension response payload.
    /// </summary>
    public sealed class ExtendResponsePayload : ExtendPduPayload
    {
        /// <summary>
        ///     Extension response payload TLV type.
        /// </summary>
        public const uint TagType = 0x302;

        private const uint RequestIdTagType = 0x1;
        private const uint LastTimeTagType = 0x10;

        private readonly CalendarHashChain _calendarHashChain;
        private readonly StringTag _errorMessage;

        private readonly IntegerTag _lastTime;

        private readonly IntegerTag _requestId;
        private readonly IntegerTag _status;

        /// <summary>
        ///     Create extend response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtendResponsePayload(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid extend response payload type: " + Type);
            }

            int requestIdCount = 0;
            int statusCount = 0;
            int errorMessageCount = 0;
            int lastTimeCount = 0;
            int calendarHashChainCount = 0;

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
                    case LastTimeTagType:
                        _lastTime = new IntegerTag(this[i]);
                        this[i] = _lastTime;
                        lastTimeCount++;
                        break;
                    case CalendarHashChain.TagType:
                        _calendarHashChain = new CalendarHashChain(this[i]);
                        this[i] = _calendarHashChain;
                        calendarHashChainCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new InvalidTlvStructureException("Only one request id must exist in extend response payload");
            }

            if (statusCount != 1)
            {
                throw new InvalidTlvStructureException("Only one status code must exist in extend response payload");
            }

            if (errorMessageCount > 1)
            {
                throw new InvalidTlvStructureException("Only one error message is allowed in extend response payload");
            }

            if (lastTimeCount > 1)
            {
                throw new InvalidTlvStructureException("Only one last time is allowed in extend response payload");
            }

            if (_status.Value == 0 && calendarHashChainCount != 1)
            {
                throw new InvalidTlvStructureException(
                    "Only one calendar hash chain must exist in extend response payload");
            }

            if (_status.Value != 0 && calendarHashChainCount != 0)
            {
                throw new InvalidTlvStructureException(
                    "Calendar hash chain should be missing when error occurs in extend response payload");
            }
        }

        /// <summary>
        ///     Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain
        {
            get { return _calendarHashChain; }
        }
    }
}