using System;
using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    public class ExtendRequestPayload : ExtendPduPayload
    {
        // TODO: Better name
        public const uint TagType = 0x301;
        private const uint RequestIdTagType = 0x1;
        private const uint AggregationTimeTagType = 0x2;
        // TODO: Check if correct
        private const uint PublicationTimeTagType = 0x3;

        private readonly IntegerTag _requestId;
        private readonly IntegerTag _aggregationTime;
        private readonly IntegerTag _publicationTime;

        public ExtendRequestPayload(TlvTag tag) : base(tag)
        {
        }

        // Create correct constructor
        public ExtendRequestPayload(ulong aggregationTime) : base(TagType, false, false, new List<TlvTag>())
        {
            _requestId = new IntegerTag(RequestIdTagType, false, false, Util.GetRandomUnsignedLong());
            AddTag(_requestId);

            _aggregationTime = new IntegerTag(AggregationTimeTagType, false, false, aggregationTime);
            AddTag(_aggregationTime);
        }

        protected override void CheckStructure()
        {
            throw new NotImplementedException();
        }

    }
}
