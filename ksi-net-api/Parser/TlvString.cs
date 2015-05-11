using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class TlvString : ITlvContent
    {
        private string _value;

        public TlvString(string value)
        {
            _value = value;
        }

        public TlvString(byte[] data)
        {
            Decode(data);
        }

        public byte[] Encode()
        {
            var stringBytes = Encoding.UTF8.GetBytes(_value);
            var bytes = new byte[stringBytes.Length + 1];
            Array.Copy(stringBytes, 0, bytes, 0, stringBytes.Length);
            return bytes;
        }

        public void Decode(byte[] valueBytes)
        {
            if (valueBytes.Length > 0 && valueBytes[valueBytes.Length - 1] == 0)
            {
                _value = Encoding.UTF8.GetString(valueBytes, 0, valueBytes.Length - 1);
            }
            else
            {
                // TODO: Use correct exception
                throw new FormatException("String must be null terminated");
            }

        }
    }
}