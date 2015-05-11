using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class SignatureData : CompositeTag
    {
        protected StringTag SignatureType;

        protected RawTag SignatureValue;

        protected RawTag CertificateId;

        protected StringTag CertificateRepositoryUri;

        public SignatureData(ITlvTag tag) : base(tag)
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
                        SignatureValue = new RawTag(Value[i]);
                        Value[i] = SignatureValue;
                        break;
                    case 0x3:
                        CertificateId = new RawTag(Value[i]);
                        Value[i] = CertificateId;
                        break;
                    case 0x4:
                        CertificateRepositoryUri = new StringTag(Value[i]);
                        Value[i] = CertificateRepositoryUri;
                        break;
                }
            }
        }
    }
}