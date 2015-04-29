
using System;
using System.Text;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Parser
{
    public class ImprintTag : TlvTag<DataHash>
    {
        public ImprintTag(ITlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        public sealed override void DecodeValue(byte[] valueBytes)
        {
            Value = new DataHash(valueBytes);
        }

        public sealed override byte[] EncodeValue()
        {
            return Value.Imprint;
        }

        public sealed override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append(base.ToString());
            builder.Append("0x").Append(Value == null ? null : Util.Util.ConvertByteArrayToHex(Value.Imprint));
            return builder.ToString();
        }
    }
}
