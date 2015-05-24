using System.Text;

namespace Guardtime.KSI.Parser
{
    public class IntegerTag : TlvTag
    {
        public new ulong Value;

        public IntegerTag(byte[] bytes) : this(null, bytes)
        {
        }

        public IntegerTag(TlvTag parent, byte[] bytes) : base(parent, bytes)
        {
            byte[] data = base.Value;
            Value = Util.Util.DecodeUnsignedLong(data, 0, data.Length);
        }

        public IntegerTag(TlvTag tag) : this(null, tag)
        {
        }

        public IntegerTag(TlvTag parent, TlvTag tag) : base(parent, tag)
        {
            byte[] data = tag.EncodeValue();
            Value = Util.Util.DecodeUnsignedLong(data, 0, data.Length);
        }

        public IntegerTag(uint type, bool nonCritical, bool forward, ulong value)
            : this(null, type, nonCritical, forward, value)
        {
        }

        public IntegerTag(TlvTag parent, uint type, bool nonCritical, bool forward, ulong value)
            : base(parent, type, nonCritical, forward, Util.Util.EncodeUnsignedLong(value))
        {
            Value = value;
        }

        public override byte[] EncodeValue()
        {
            return Util.Util.EncodeUnsignedLong(Value);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return Value.GetHashCode() + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        public override bool Equals(object obj)
        {
            IntegerTag tag = obj as IntegerTag;
            if (tag == null)
            {
                return false;
            }

            return tag.Type == Type &&
                   tag.Forward == Forward &&
                   tag.NonCritical == NonCritical &&
                   tag.Value == Value;
        }

        public sealed override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("TLV[0x").Append(Type.ToString("X"));

            if (NonCritical)
            {
                builder.Append(",N");
            }

            if (Forward)
            {
                builder.Append(",F");
            }

            builder.Append("]:");
            builder.Append("i").Append(Value);
            return builder.ToString();
        }

    }

}
