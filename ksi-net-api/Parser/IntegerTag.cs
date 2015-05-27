using System.Text;

namespace Guardtime.KSI.Parser
{
    public class IntegerTag : TlvTag
    {
        private readonly ulong _value;

        public new ulong Value
        {
            get { return _value; }
        }

        // TODO: Fix problems with base null and encode returning null
        public IntegerTag(byte[] bytes) : base(bytes)
        {
            byte[] data = base.Value;
            _value = Util.Util.DecodeUnsignedLong(data, 0, data.Length);
        }

        public IntegerTag(TlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            _value = Util.Util.DecodeUnsignedLong(data, 0, data.Length);
        }

        public IntegerTag(uint type, bool nonCritical, bool forward, ulong value)
            : base(type, nonCritical, forward, Util.Util.EncodeUnsignedLong(value))
        {
            _value = value;
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
