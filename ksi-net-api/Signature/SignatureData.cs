using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class SignatureData : CompositeTag
    {
        protected StringTag SignatureType;

        protected TlvTag SignatureValue;

        protected TlvTag CertificateId;

        protected StringTag CertificateRepositoryUri;

        public SignatureData(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < this.Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x1:
                        SignatureType = new StringTag(this[i]);
                        this[i] = SignatureType;
                        break;
                    case 0x2:
                        SignatureValue = this[i];
                        break;
                    case 0x3:
                        CertificateId = this[i];
                        this[i] = CertificateId;
                        break;
                    case 0x4:
                        CertificateRepositoryUri = new StringTag(this[i]);
                        this[i] = CertificateRepositoryUri;
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