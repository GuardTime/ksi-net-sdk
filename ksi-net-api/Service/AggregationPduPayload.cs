using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    internal abstract class AggregationPduPayload : CompositeTag
    {
        protected AggregationPduPayload(uint type, bool nonCritical, bool forward) : base(type, nonCritical, forward)
        {
        }

        protected AggregationPduPayload(byte[] bytes) : base(bytes)
        {
        }

        protected AggregationPduPayload(TlvTag tag) : base(tag)
        {
        }

        
    }
}