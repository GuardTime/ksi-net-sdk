using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    public abstract class AggregationPduPayload : CompositeTag
    {

        protected AggregationPduPayload(byte[] bytes) : base(bytes)
        {
        }

        protected AggregationPduPayload(TlvTag tag) : base(tag)
        {
        }

        protected AggregationPduPayload(uint type, bool nonCritical, bool forward, List<TlvTag> value) : base(type, nonCritical, forward, value)
        {
        }

    }
}