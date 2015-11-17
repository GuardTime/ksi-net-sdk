using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation Error payload TLV element.
    /// </summary>
    public abstract class ErrorPayload : KsiPduPayload
    {
        /// <summary>
        ///     Create aggregation error payload TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <param name="expectedTagType">expected tag type</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        protected ErrorPayload(ITlvTag tag, uint expectedTagType) : base(tag)
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
                        IntegerTag statusTag = new IntegerTag(this[i]);
                        Status = statusTag.Value;
                        statusCount++;
                        break;
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        StringTag errorMessageTag = new StringTag(this[i]);
                        ErrorMessage = errorMessageTag.Value;
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
        public ulong Status { get; }

        /// <summary>
        ///     Get aggregation error message if it exists.
        /// </summary>
        public string ErrorMessage { get; }
    }
}