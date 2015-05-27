using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class CertificateRecord : CompositeTag
    {
        private RawTag _certificateId;
        private RawTag _x509Certificate;

        public RawTag CertificateId
        {
            get
            {
                return _certificateId;
            }

            set
            {
                PutTag(value, _certificateId);
                _certificateId = value;
            }
        }

        public RawTag X509Certificate
        {
            get
            {
                return _x509Certificate;
            }

            set
            {
                PutTag(value, _x509Certificate);
                _x509Certificate = value;
            }
        }

        public CertificateRecord(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        _certificateId = new RawTag(Value[i]);
                        Value[i] = _certificateId;
                        break;
                    case 0x2:
                        _x509Certificate = new RawTag(Value[i]);
                        Value[i] = _x509Certificate;
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            throw new System.NotImplementedException();
        }
    }
}