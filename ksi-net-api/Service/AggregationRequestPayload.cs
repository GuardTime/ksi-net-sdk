using System;
using System.Collections.Generic;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    public class AggregationRequestPayload : AggregationPduPayload
    {
        private IntegerTag _requestId;
        private ImprintTag _requestHash;
        private IntegerTag _requestLevel;
        private RawTag _config;

        public AggregationRequestPayload(TlvTag tag) : base(tag)
        {
        }

        // Create correct constructor
        public AggregationRequestPayload() : base(0x201, false, false, new List<TlvTag>())
        {
            _requestId = new IntegerTag(0x1, false, false, Util.Util.GetRandomUnsignedLong());
            this.AddTag(_requestId);

            _requestHash = new ImprintTag(0x2, false, false, new DataHash(HashAlgorithm.Sha2256, new byte[] {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}));
            this.AddTag(_requestHash);
        }

        protected override void CheckStructure()
        {
            throw new NotImplementedException();
        }

    }
}
