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
        protected ErrorPayload(ITlvTag tag, uint expectedTagType) : base(tag)
        {
            if (Type != expectedTagType)
            {
                throw new TlvException("Invalid aggregation error type(" + Type + ").");
            }

            int statusCount = 0;
            int errorMessageCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.KsiPduPayload.StatusTagType:
                        IntegerTag statusTag = new IntegerTag(childTag);
                        Status = statusTag.Value;
                        statusCount++;
                        break;
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        StringTag errorMessageTag = new StringTag(childTag);
                        ErrorMessage = errorMessageTag.Value;
                        errorMessageCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
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