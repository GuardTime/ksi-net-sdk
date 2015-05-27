using System;
using System.Collections.Generic;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    public class AggregationRequest : AggregationPduPayload
    {
        private IntegerTag _requestId;
        private ImprintTag _requestHash;
        private IntegerTag _requestLevel;
        private RawTag _config;

        public AggregationRequest(byte[] bytes) : base(bytes)
        {
        }

        public AggregationRequest(TlvTag tag) : base(tag)
        {
        }

        // Create correct constructor
        public AggregationRequest() : base(0x201, false, false, new List<TlvTag>())
        {
            _requestId = new IntegerTag(0x1, false, false, Util.Util.GetRandomUnsignedLong());
            Value.Add(_requestId);

            _requestHash = new ImprintTag(0x2, false, false, new DataHash(HashAlgorithm.Sha2256, new byte[] {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}));
            Value.Add(_requestHash);
        }

        protected override void CheckStructure()
        {
            throw new NotImplementedException();
        }

    }
}
