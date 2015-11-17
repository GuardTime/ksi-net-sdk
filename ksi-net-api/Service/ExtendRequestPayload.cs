using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extend request payload.
    /// </summary>
    public sealed class ExtendRequestPayload : ExtendPduPayload
    {
        private readonly IntegerTag _aggregationTime;
        private readonly IntegerTag _publicationTime;
        private readonly IntegerTag _requestId;

        /// <summary>
        ///     Create extend request payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public ExtendRequestPayload(TlvTag tag) : base(tag)
        {
            if (Type != Constants.ExtendRequestPayload.TagType)
            {
                throw new TlvException("Invalid extend request payload type(" + Type + ").");
            }

            int requestIdCount = 0;
            int aggregationTimeCount = 0;
            int publicationTimeCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case Constants.ExtendRequestPayload.RequestIdTagType:
                        _requestId = new IntegerTag(this[i]);
                        requestIdCount++;
                        break;
                    case Constants.ExtendRequestPayload.AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        aggregationTimeCount++;
                        break;
                    case Constants.ExtendRequestPayload.PublicationTimeTagType:
                        _publicationTime = new IntegerTag(this[i]);
                        publicationTimeCount++;
                        break;
                    default:
                        VerifyUnknownTag(this[i]);
                        break;
                }
            }

            if (requestIdCount != 1)
            {
                throw new TlvException("Only one request id must exist in extend request payload.");
            }

            if (aggregationTimeCount != 1)
            {
                throw new TlvException("Only one aggregation time must exist in extend request payload.");
            }

            if (publicationTimeCount > 1)
            {
                throw new TlvException("Only one publication time is allowed in extend request payload.");
            }
        }

        /// <summary>
        ///     Create extend request payload from aggregation time and publication time.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        public ExtendRequestPayload(ulong aggregationTime, ulong publicationTime) : base(Constants.ExtendRequestPayload.TagType, false, false, new List<TlvTag>()
        {
            new IntegerTag(Constants.ExtendRequestPayload.RequestIdTagType, false, false, Util.GetRandomUnsignedLong()),
            new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, aggregationTime),
            new IntegerTag(Constants.ExtendRequestPayload.PublicationTimeTagType, false, false, publicationTime)
        })
        {
            _requestId = (IntegerTag)this[0];
            _aggregationTime = (IntegerTag)this[1];
            _publicationTime = (IntegerTag)this[2];
        }

        /// <summary>
        ///     Create extend request payload from aggregation time.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        public ExtendRequestPayload(ulong aggregationTime) : base(Constants.ExtendRequestPayload.TagType, false, false, new List<TlvTag>()
        {
            new IntegerTag(Constants.ExtendRequestPayload.RequestIdTagType, false, false, Util.GetRandomUnsignedLong()),
            new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, aggregationTime),
        })
        {
            _requestId = (IntegerTag)this[0];
            _aggregationTime = (IntegerTag)this[1];
        }

        /// <summary>
        ///     Get request ID.
        /// </summary>
        public ulong RequestId
        {
            get { return _requestId.Value; }
        }

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        public ulong AggregationTime
        {
            get { return _aggregationTime.Value; }
        }

        /// <summary>
        ///     Get publication time if exists otherwise null.
        /// </summary>
        public ulong? PublicationTime
        {
            get { return _publicationTime?.Value; }
        }
    }
}