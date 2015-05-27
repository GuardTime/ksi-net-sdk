using System.Text;

namespace Guardtime.KSI.Parser
{
    public class StringTag : TlvTag
    {
        private readonly string _value;
        public new string Value
        {
            get { return _value; }
        }

        public StringTag(byte[] bytes) : base(bytes)
        {
            _value = Util.Util.DecodeNullTerminatedUtf8String(base.Value);
        }

        public StringTag(TlvTag tag) : base(tag)
        {
            _value = Util.Util.DecodeNullTerminatedUtf8String(tag.EncodeValue());
        }

        public StringTag(uint type, bool nonCritical, bool forward, string value)
            : base(type, nonCritical, forward, Util.Util.EncodeNullTerminatedUtf8String(value))
        {
            _value = value;
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
