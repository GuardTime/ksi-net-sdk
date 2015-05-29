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
        }

        public RawTag X509Certificate
        {
            get
            {
                return _x509Certificate;
            }
        }

        public CertificateRecord(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x1:
                        _certificateId = new RawTag(this[i]);
                        this[i] = _certificateId;
                        break;
                    case 0x2:
                        _x509Certificate = new RawTag(this[i]);
                        this[i] = _x509Certificate;
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