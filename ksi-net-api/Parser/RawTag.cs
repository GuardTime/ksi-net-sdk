using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class RawTag : TlvTag
    {
        public byte[] Value
        {
            get { return ValueBytes; }
            set { ValueBytes = value; }
        }

        public RawTag(byte[] bytes) : base(bytes)
        {
        }

        public RawTag(TlvTag tag) : base(tag)
        {
        }

        public RawTag(uint type, bool nonCritical, bool forward, byte[] data) : base(type, nonCritical, forward, data)
        {
        }

        public override byte[] EncodeValue()
        {
            return Value;
        }
    }

}
