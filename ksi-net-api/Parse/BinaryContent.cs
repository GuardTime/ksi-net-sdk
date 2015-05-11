using System;
using System.Collections.Generic;
using System.Text;

namespace Guardtime.KSI.Parse
{
    class BinaryContent : ITlvContent
    {
        private byte[] _value;

        public BinaryContent(byte[] bytes)
        {
            _value = bytes;
        }

        public byte[] EncodeValue()
        {
            return _value;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();
            if (_value != null)
            {
                builder.Append("0x").Append(Util.Util.ConvertByteArrayToHex(_value));
            }
            return builder.ToString();
        }
    }
}
