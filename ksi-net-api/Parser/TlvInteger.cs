using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class TlvInteger : ITlvContent
    {
        private ulong _value;

        public TlvInteger(ulong value)
        {
            _value = value;
        }

        public TlvInteger(byte[] data)
        {
            Decode(data);
        }

        public byte[] Encode()
        {
            return Util.Util.EncodeUnsignedLong(_value);
        }

        public void Decode(byte[] valueBytes)
        {
            _value = Util.Util.DecodeUnsignedLong(valueBytes, 0, valueBytes.Length);
        }
    }
}