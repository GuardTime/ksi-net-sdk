
using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class StringTag : TlvTag<string>
    {
        public StringTag(ITlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        public sealed override void DecodeValue(byte[] valueBytes)
        {
            if (valueBytes.Length > 0 && valueBytes[valueBytes.Length - 1] == 0)
            {
                Value = Encoding.UTF8.GetString(valueBytes, 0, valueBytes.Length - 1);
            }
            else
            {
                // TODO: Catch exception
                throw new FormatException("String must be null terminated");
            }
            
        }

        public sealed override byte[] EncodeValue()
        {
            return Encoding.UTF8.GetBytes(Value);
        }

        public sealed override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append(base.ToString());
            builder.Append("\"").Append(Value).Append("\"");
            return builder.ToString();
        }

        public override bool Equals(object obj)
        {
            if (obj == null || obj.GetType() != GetType()) return false;
            var b = (StringTag)obj;
            return b.Type == Type &&
                   b.Forward == Forward &&
                   b.NonCritical == NonCritical &&
                   b.Value.Equals(Value);
        }
    }
}
