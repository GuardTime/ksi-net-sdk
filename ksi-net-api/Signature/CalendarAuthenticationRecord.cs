using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    public class CalendarAuthenticationRecord : CompositeTag
    {
        protected PublicationData PublicationData;

        protected SignatureData SignatureData;

        public CalendarAuthenticationRecord(ITlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x10:
                        Value[i] = PublicationData = new PublicationData(Value[i]);
                        break;
                    case 0xb:
                        Value[i] = SignatureData = new SignatureData(Value[i]);
                        break;
                }
            }
        }
    }
}