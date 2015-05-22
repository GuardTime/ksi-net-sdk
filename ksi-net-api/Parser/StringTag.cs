using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class StringTag : TlvTag
    {
        public string Value;

        public StringTag(byte[] bytes) : base(bytes)
        {
            Util.Util.DecodeNullTerminatedUtf8String(ValueBytes);
        }

        public StringTag(TlvTag tag) : base(tag)
        {
            Util.Util.DecodeNullTerminatedUtf8String(tag.EncodeValue());
        }

        public StringTag(uint type, bool nonCritical, bool forward, string value)
            : base(type, nonCritical, forward, Util.Util.EncodeNullTerminatedUtf8String(value))
        {
            Value = value;
        }

        public override byte[] EncodeValue()
        {
            return Util.Util.EncodeNullTerminatedUtf8String(Value);
        }

        public override bool Equals(object obj)
        {
            var tag = obj as StringTag;
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
            var builder = new StringBuilder();
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
