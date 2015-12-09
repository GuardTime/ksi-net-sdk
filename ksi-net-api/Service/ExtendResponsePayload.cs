﻿using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extension response payload.
    /// </summary>
    public sealed class ExtendResponsePayload : KsiPduPayload
    {
        private readonly StringTag _errorMessage;
        private readonly IntegerTag _lastTime;
        private readonly IntegerTag _requestId;
        private readonly IntegerTag _status;

        /// <summary>
        ///     Create extend response payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ExtendResponsePayload(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.ExtendResponsePayload.TagType)
            {
                throw new TlvException("Invalid extend response payload type(" + Type + ").");
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
                    case Constants.ExtendResponsePayload.RequestIdTagType:
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
                    case Constants.ExtendResponsePayload.LastTimeTagType:
                        _lastTime = new IntegerTag(this[i]);
                        lastTimeCount++;
                        break;
                    case Constants.CalendarHashChain.TagType:
                        CalendarHashChain = new CalendarHashChain(this[i]);
                        calendarHashChainCount++;
                        break;
                    default:
                        VerifyUnknownTag(this[i]);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new TlvException("Only one request id must exist in extend response payload.");
            }

            if (statusCount != 1)
            {
                throw new TlvException("Only one status code must exist in extend response payload.");
            }

            if (errorMessageCount > 1)
            {
                throw new TlvException("Only one error message is allowed in extend response payload.");
            }

            if (lastTimeCount > 1)
            {
                throw new TlvException("Only one last time is allowed in extend response payload.");
            }

            if (_status.Value == 0 && calendarHashChainCount != 1)
            {
                throw new TlvException(
                    "Only one calendar hash chain must exist in extend response payload.");
            }

            if (_status.Value != 0 && calendarHashChainCount != 0)
            {
                throw new TlvException(
                    "Calendar hash chain should be missing when error occurs in extend response payload.");
            }
        }

        /// <summary>
        ///     Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain { get; }

        /// <summary>
        ///     Get error message if it exists.
        /// </summary>
        public string ErrorMessage => _errorMessage?.Value;

        /// <summary>
        ///     Get last time if it exists.
        /// </summary>
        public ulong? LastTime => _lastTime?.Value;

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId => _requestId.Value;

        /// <summary>
        ///     Get status code.
        /// </summary>
        public ulong Status => _status.Value;
    }
}