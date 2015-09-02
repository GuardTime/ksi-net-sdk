using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Extend request payload.
    /// </summary>
    public sealed class ExtendRequestPayload : ExtendPduPayload
    {
        /// <summary>
        /// Extend request payload TLV type.
        /// </summary>
        public const uint TagType = 0x301;

        private const uint RequestIdTagType = 0x1;
        private const uint AggregationTimeTagType = 0x2;
        // TODO: Check if correct
        private const uint PublicationTimeTagType = 0x3;

        private readonly IntegerTag _requestId;
        private readonly IntegerTag _aggregationTime;
        private readonly IntegerTag _publicationTime;

        /// <summary>
        /// Create extend request payload from aggregation time and publication time.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        public ExtendRequestPayload(ulong aggregationTime, ulong publicationTime) : this(aggregationTime)
        {
            _publicationTime = new IntegerTag(PublicationTimeTagType, false, false, publicationTime);
            AddTag(_publicationTime);
        }

        /// <summary>
        /// Create extend request payload from aggregation time.
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        public ExtendRequestPayload(ulong aggregationTime) : base(TagType, false, false, new List<TlvTag>())
        {
            _requestId = new IntegerTag(RequestIdTagType, false, false, Util.GetRandomUnsignedLong());
            AddTag(_requestId);

            _aggregationTime = new IntegerTag(AggregationTimeTagType, false, false, aggregationTime);
            AddTag(_aggregationTime);
        }

    }
}
