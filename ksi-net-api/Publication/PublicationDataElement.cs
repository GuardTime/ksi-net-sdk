using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationDataElement : TlvComposite
    {
        private TlvInteger _publicationTime;
        private TlvImprint _publicationHash;

        public ITlvContent GetMember(uint type, byte[] valueBytes)
        {
            switch (type)
            {
                case 0x2:
                    _publicationTime = new TlvInteger(valueBytes);
                    return _publicationTime;
                case 0x4:
                    _publicationHash = new TlvImprint(valueBytes);
                    return _publicationHash;
            }

            return null;
        }

        
    }
}
