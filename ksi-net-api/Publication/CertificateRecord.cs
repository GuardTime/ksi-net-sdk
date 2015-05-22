using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class CertificateRecord : CompositeTag
    {
        public TlvTag CertificateId;
        public TlvTag X509Certificate;

        public CertificateRecord(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        CertificateId = Value[i];
                        break;
                    case 0x2:
                        X509Certificate = Value[i];
                        break;
                }
            }
        }

        public override bool IsValidStructure()
        {
            throw new System.NotImplementedException();
        }
    }
}