using System.Text;

namespace Guardtime.KSI.Parser
{
    public class StringTag : TlvTag
    {
        public new string Value;

        public StringTag(byte[] bytes) : this(null, bytes)
        {
        }

        public StringTag(TlvTag parent, byte[] bytes) : base(parent, bytes)
        {
            Value = Util.Util.DecodeNullTerminatedUtf8String(base.Value);
        }

        public StringTag(TlvTag tag) : this(null, tag)
        {
        }

        public StringTag(TlvTag parent, TlvTag tag) : base(parent, tag)
        {
            Value = Util.Util.DecodeNullTerminatedUtf8String(tag.EncodeValue());
        }

        public StringTag(uint type, bool nonCritical, bool forward, string value)
            : this(null, type, nonCritical, forward, value)
        {
        }

        public StringTag(TlvTag parent, uint type, bool nonCritical, bool forward, string value)
            : base(parent, type, nonCritical, forward, Util.Util.EncodeNullTerminatedUtf8String(value))
        {
            Value = value;
        }

        public override byte[] EncodeValue()
        {
            return Util.Util.EncodeNullTerminatedUtf8String(Value);
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
            StringTag tag = obj as StringTag;
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
            builder.Append("\"").Append(Value).Append("\"");
            return builder.ToString();
        }

    }

}
