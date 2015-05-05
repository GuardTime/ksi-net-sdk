using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    public class CalendarAuthenticationRecord : ICompositeTag
    {
        protected CompositeTag<PublicationData> publicationData;

        protected CompositeTag<SignatureData> signatureData;

        public ITlvTag GetMember(ITlvTag tag)
        {
            switch (tag.Type)
            {
                case 0x10:
                    publicationData = new CompositeTag<PublicationData>(tag, new PublicationData());
                    return publicationData;
                case 0xb:
                    signatureData = new CompositeTag<SignatureData>(tag, new SignatureData());
                    return signatureData;
            }

            return null;
        }
    }
}