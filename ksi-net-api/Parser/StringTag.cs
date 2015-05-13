using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class StringTag : TlvTag
    {
        public new string Value;

        public StringTag(byte[] bytes) : base(bytes)
        {
            DecodeValue(base.EncodeValue());
        }

        public StringTag(TlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        public void DecodeValue(byte[] bytes)
        {
            if (bytes.Length > 0 && bytes[bytes.Length - 1] == 0)
            {
                Value = Encoding.UTF8.GetString(bytes, 0, bytes.Length - 1);
            }
            else
            {
                // TODO: Use correct exception
                throw new FormatException("String must be null terminated");
            }

        }

        public override byte[] EncodeValue()
        {
            var stringBytes = Encoding.UTF8.GetBytes(Value);
            var bytes = new byte[stringBytes.Length + 1];
            Array.Copy(stringBytes, 0, bytes, 0, stringBytes.Length);
            return bytes;
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
