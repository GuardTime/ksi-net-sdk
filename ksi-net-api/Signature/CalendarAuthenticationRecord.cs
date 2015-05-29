using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    public class CalendarAuthenticationRecord : CompositeTag
    {
        protected PublicationData PublicationData;
        protected SignatureData SignatureData;

        public CalendarAuthenticationRecord(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < this.Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x10:
                        PublicationData = new PublicationData(this[i]);
                        this[i] = PublicationData;
                        break;
                    case 0xb:
                        SignatureData = new SignatureData(this[i]);
                        this[i] = SignatureData;
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            // TODO:
        }
    }
}