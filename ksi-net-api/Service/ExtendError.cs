using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extension error payload.
    /// </summary>
    public sealed class ExtendError : ExtendPduPayload
    {
        /// <summary>
        ///     Extension error payload TLV type.
        /// </summary>
        public const uint TagType = 0x303;

        private readonly StringTag _errorMessage;
        private readonly IntegerTag _status;

        /// <summary>
        ///     Create extend error payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public ExtendError(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new TlvException("Invalid extend error type(" + Type + ").");
            }

            int statusCount = 0;
            int errorMessageCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case StatusTagType:
                        _status = new IntegerTag(this[i]);
                        statusCount++;
                        break;
                    case ErrorMessageTagType:
                        _errorMessage = new StringTag(this[i]);
                        errorMessageCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (statusCount != 1)
            {
                throw new TlvException("Only one status code must exist in extend error.");
            }

            if (errorMessageCount > 1)
            {
                throw new TlvException("Only one error message is allowed in extend error.");
            }
        }

        /// <summary>
        ///     Get error message.
        /// </summary>
        public string ErrorMessage
        {
            get { return _errorMessage == null ? null : _errorMessage.Value; }
        }

        /// <summary>
        ///     Get status code.
        /// </summary>
        public ulong Status
        {
            get { return _status.Value; }
        }
    }
}