
using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class IntegerTag : TlvTag<ulong>
    {
        public IntegerTag(ITlvTag tag)
            : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        public sealed override void DecodeValue(byte[] valueBytes)
        {
            Value = Util.Util.DecodeUnsignedLong(valueBytes, 0, valueBytes.Length);
        }

        public sealed override byte[] EncodeValue()
        {
            return Util.Util.EncodeUnsignedLong(Value);
        }

        public sealed override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append(base.ToString());
            builder.Append("i").Append(Value);
            return builder.ToString();
        }

        public override bool Equals(object obj)
        {
            if (obj == null || obj.GetType() != GetType()) return false;
            var b = (IntegerTag)obj;
            return b.Type == Type &&
                   b.Forward == Forward &&
                   b.NonCritical == NonCritical &&
                   b.Value.Equals(Value);
        }
    }
}
