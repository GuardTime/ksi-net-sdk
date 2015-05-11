using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Parser
{
    public class TlvImprint : ITlvContent
    {
        private DataHash _value;

        public TlvImprint(DataHash hash)
        {
            _value = hash;
        }

        public TlvImprint(byte[] data)
        {
            Decode(data);
        }

        public byte[] Encode()
        {
            return _value.Imprint;
        }

        public void Decode(byte[] valueBytes)
        {
            _value = new DataHash(valueBytes);
        }
    }
}