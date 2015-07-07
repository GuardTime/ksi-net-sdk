
using Guardtime.KSI.Parser;
using System.Collections.Generic;

namespace Guardtime.KSI.Service
{
    public abstract class ExtendPduPayload : KsiPduPayload
    {
        protected ExtendPduPayload(TlvTag tag) : base(tag)
        {
        }

        protected ExtendPduPayload(uint type, bool nonCritical, bool forward, List<TlvTag> value) : base(type, nonCritical, forward, value)
        {
        }
    }
}