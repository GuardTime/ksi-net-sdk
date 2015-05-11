using System.Collections.Generic;
using System.IO;

namespace Guardtime.KSI.Parser
{
    public abstract class TlvComposite : ITlvContent
    {
        private List<TlvElement> _tlvElements;

        protected TlvComposite()
        {
            _tlvElements = new List<TlvElement>();
        }

        public byte[] Encode()
        {
            throw new System.NotImplementedException();
        }

        public void Decode(byte[] bytes)
        {
            using (var reader = new TlvReaderElement(new MemoryStream(bytes)))
            {
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    var element = reader.ReadTag();
                    _tlvElements.Add(element);
                }
                
            }
        }
    }
}