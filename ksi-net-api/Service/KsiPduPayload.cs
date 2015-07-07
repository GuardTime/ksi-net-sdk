using Guardtime.KSI.Parser;
using System.Collections.Generic;

namespace Guardtime.KSI.Service
{
    public abstract class KsiPduPayload : CompositeTag
    {
        // TODO: Better name
        protected const uint StatusTagType = 0x4;
        protected const uint ErrorMessageTagType = 0x5;

        protected KsiPduPayload(TlvTag tag) : base(tag)
        {
        }

        protected KsiPduPayload(uint type, bool nonCritical, bool forward, List<TlvTag> value) : base(type, nonCritical, forward, value)
        {
        }


    }
}
