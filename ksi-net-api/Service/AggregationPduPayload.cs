using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Aggregation PDU payload.
    /// </summary>
    public abstract class AggregationPduPayload : KsiPduPayload
    {
        /// <summary>
        /// Create aggregation PDU payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected AggregationPduPayload(TlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Create aggregation PDU payload from data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">is TLV non critical</param>
        /// <param name="forward">is TLV forwarded</param>
        /// <param name="value">tlv element list</param>
        protected AggregationPduPayload(uint type, bool nonCritical, bool forward, List<TlvTag> value) : base(type, nonCritical, forward, value)
        {
        }
    }
}