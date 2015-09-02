using Guardtime.KSI.Parser;
using System.Collections.Generic;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// KSI PDU payload.
    /// </summary>
    public abstract class KsiPduPayload : CompositeTag
    {
        /// <summary>
        /// Status TLV element type.
        /// </summary>
        protected const uint StatusTagType = 0x4;
        /// <summary>
        /// Error message TLV element type.
        /// </summary>
        protected const uint ErrorMessageTagType = 0x5;

        /// <summary>
        /// Create KSI PDU payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected KsiPduPayload(TlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Create KSI PDU payload from data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">is TLV non critical</param>
        /// <param name="forward">is TLV forwarded</param>
        /// <param name="value">TLV element list</param>
        protected KsiPduPayload(uint type, bool nonCritical, bool forward, List<TlvTag> value) : base(type, nonCritical, forward, value)
        {
        }


    }
}
