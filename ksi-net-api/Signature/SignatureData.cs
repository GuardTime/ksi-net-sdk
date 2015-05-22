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
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        SignatureType = new StringTag(Value[i]);
                        Value[i] = SignatureType;
                        break;
                    case 0x2:
                        SignatureValue = Value[i];
                        break;
                    case 0x3:
                        CertificateId = Value[i];
                        Value[i] = CertificateId;
                        break;
                    case 0x4:
                        CertificateRepositoryUri = new StringTag(Value[i]);
                        Value[i] = CertificateRepositoryUri;
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