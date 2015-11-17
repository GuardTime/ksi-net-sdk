using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extend PDU payload.
    /// </summary>
    public abstract class ExtendPduPayload : KsiPduPayload
    {
        /// <summary>
        ///     Create extend pdu payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected ExtendPduPayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        ///     Create extend pdu payload from data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">is TLV non critical</param>
        /// <param name="forward">is TLV forwarded</param>
        /// <param name="value">TLV element list</param>
        protected ExtendPduPayload(uint type, bool nonCritical, bool forward, List<ITlvTag> value)
            : base(type, nonCritical, forward, value)
        {
        }
    }
}