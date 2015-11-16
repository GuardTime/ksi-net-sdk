using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI PDU payload.
    /// </summary>
    public abstract class KsiPduPayload : CompositeTag
    {
        /// <summary>
        ///     Create KSI PDU payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected KsiPduPayload(TlvTag tag) : base(tag)
        {
        }

        /// <summary>
        ///     Create KSI PDU payload from data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">is TLV non critical</param>
        /// <param name="forward">is TLV forwarded</param>
        /// <param name="value">TLV element list</param>
        protected KsiPduPayload(uint type, bool nonCritical, bool forward, List<TlvTag> value)
            : base(type, nonCritical, forward, value)
        {
        }
    }
}