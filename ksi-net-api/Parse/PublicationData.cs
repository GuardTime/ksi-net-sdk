
namespace Guardtime.KSI.Parse
{
    public class PublicationData : TlvComposite
    {
        private TlvElement _publicationTime;
        private TlvElement _publicationHash;

        public PublicationData(byte[] bytes) : base(bytes)
        {
            
            for (var i = 0; i < Content.Value.Count; i++)
            {
                switch (Content.Value[i].Type)
                {
                    case 0x2:
                        _publicationTime = Content.Value[i];
                        break;
                    case 0x4:
                        _publicationHash = Content.Value[i];
                        break;
                }
            }
        }


    }
}
