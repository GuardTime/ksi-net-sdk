using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation Error payload TLV element.
    /// </summary>
    public abstract class ErrorPayload : KsiPduPayload
    {
        private readonly StringTag _errorMessage;
        private readonly IntegerTag _status;


        /// <summary>
        ///     Create aggregation error payload TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <param name="expectedTagType">expected tag type</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        protected ErrorPayload(TlvTag tag, uint expectedTagType) : base(tag)
        {
            if (Type != expectedTagType)
            {
                throw new TlvException("Invalid aggregation error type(" + Type + ").");
            }

            int statusCount = 0;
            int errorMessageCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case Constants.KsiPduPayload.StatusTagType:
                        _status = new IntegerTag(this[i]);
                        statusCount++;
                        break;
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        _errorMessage = new StringTag(this[i]);
                        errorMessageCount++;
                        break;
                    default:
                        VerifyUnknownTag(this[i]);
                        break;
                }
            }

            if (statusCount != 1)
            {
                throw new TlvException("Only one status code must exist in aggregation error.");
            }

            if (errorMessageCount > 1)
            {
                throw new TlvException("Only one error message is allowed in aggregation error.");
            }
        }

        /// <summary>
        ///     Get aggregation error status code.
        /// </summary>
        public ulong Status
        {
            get { return _status.Value; }
        }

        /// <summary>
        ///     Get aggregation error message if it exists.
        /// </summary>
        public string ErrorMessage
        {
            get { return _errorMessage?.Value; }
        }
    }
}