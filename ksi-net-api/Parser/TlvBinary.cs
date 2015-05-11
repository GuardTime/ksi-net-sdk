namespace Guardtime.KSI.Parser
{
    internal class TlvBinary : ITlvContent
    {
        private readonly byte[] _data;

        public TlvBinary(byte[] data)
        {
            _data = data;
        }

        public byte[] Encode()
        {
            return _data;
        }
    }
}