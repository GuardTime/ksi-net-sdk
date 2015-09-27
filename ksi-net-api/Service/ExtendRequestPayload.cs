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
        /// <summary>
        ///     Extend request payload TLV type.
        /// </summary>
        public const uint TagType = 0x301;

        private const uint RequestIdTagType = 0x1;
        private const uint AggregationTimeTagType = 0x2;
        private const uint PublicationTimeTagType = 0x3;

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
            if (Type != TagType)
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
                    case RequestIdTagType:
                        _requestId = new IntegerTag(this[i]);
                        this[i] = _requestId;
                        requestIdCount++;
                        break;
                    case AggregationTimeTagType:
                        _aggregationTime = new IntegerTag(this[i]);
                        this[i] = _aggregationTime;
                        aggregationTimeCount++;
                        break;
                    case PublicationTimeTagType:
                        _publicationTime = new IntegerTag(this[i]);
                        this[i] = _publicationTime;
                        publicationTimeCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
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
        public ExtendRequestPayload(ulong aggregationTime, ulong publicationTime) : this(aggregationTime)
        {
            _publicationTime = new IntegerTag(PublicationTimeTagType, false, false, publicationTime);
            AddTag(_publicationTime);
        }

        /// <summary>
        ///     Create extend request payload from aggregation time.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        public ExtendRequestPayload(ulong aggregationTime) : base(TagType, false, false, new List<TlvTag>())
        {
            _requestId = new IntegerTag(RequestIdTagType, false, false, Util.GetRandomUnsignedLong());
            AddTag(_requestId);

            _aggregationTime = new IntegerTag(AggregationTimeTagType, false, false, aggregationTime);
            AddTag(_aggregationTime);
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
            get { return _publicationTime == null ? (ulong?) null : _publicationTime.Value; }
        }
    }
}