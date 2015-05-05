
using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Represents a TLV element that contains raw byte data.
    /// </summary>
    public class RawTag : TlvTag<byte[]>
    {
        
        public RawTag(ITlvTag tag)
            : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        public RawTag(uint type, bool nonCritical, bool forward, byte[] value) : base(type, nonCritical, forward, value)
        {
        }

        public sealed override void DecodeValue(byte[] valueBytes)
        {
            Value = valueBytes;
        }


        public sealed override byte[] EncodeValue()
        {
            return Value;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append(base.ToString());
            if (Value != null)
            {
                builder.Append("0x").Append(Util.Util.ConvertByteArrayToHex(Value));
            }
            return builder.ToString();
        }

        public override bool Equals(object obj)
        {
            if (obj == null || obj.GetType() != GetType()) return false;
            var b = (RawTag)obj;
            return b.Type == Type &&
                   b.Forward == Forward &&
                   b.NonCritical == NonCritical &&
                   Util.Util.IsArrayEqual(b.Value, Value);
        }
    }

}
