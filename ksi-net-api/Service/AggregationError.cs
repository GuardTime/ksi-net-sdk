﻿using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation Error payload TLV element.
    /// </summary>
    public sealed class AggregationError : AggregationPduPayload
    {
        /// <summary>
        ///     Aggregation error payload TLV type.
        /// </summary>
        public const uint TagType = 0x203;

        private readonly StringTag _errorMessage;
        private readonly IntegerTag _status;

        /// <summary>
        ///     Create aggregation error payload TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public AggregationError(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new TlvException("Invalid aggregation error type(" + Type + ").");
            }

            int statusCount = 0;
            int errorMessageCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
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
                    default:
                        VerifyCriticalFlag(this[i]);
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
            get { return _errorMessage == null ? null : _errorMessage.Value; }
        }
    }
}