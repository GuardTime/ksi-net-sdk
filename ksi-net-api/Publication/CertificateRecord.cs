using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class CertificateRecord : CompositeTag
    {
        private TlvTag _certificateId;

        private TlvTag _x509Certificate;

        public CertificateRecord(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        _certificateId = Value[i];
                        break;
                    case 0x2:
                        _x509Certificate = Value[i];
                        break;
                }
            }
        }
    }
}