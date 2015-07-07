using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class CertificateRecord : CompositeTag
    {
        // TODO: Better name
        public const uint TagType = 0x702;
        private const uint CertificateIdTagType = 0x1;
        private const uint X509CertificateTagType = 0x2;

        private readonly RawTag _certificateId;
        private readonly RawTag _x509Certificate;

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
                    case CertificateIdTagType:
                        _certificateId = new RawTag(this[i]);
                        this[i] = _certificateId;
                        break;
                    case X509CertificateTagType:
                        _x509Certificate = new RawTag(this[i]);
                        this[i] = _x509Certificate;
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid certificate record type: " + Type);
            }

            uint[] tags = new uint[2];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case CertificateIdTagType:
                        tags[0]++;
                        break;
                    case X509CertificateTagType:
                        tags[1]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] != 1)
            {
                throw new InvalidTlvStructureException("Only one certificate id must exist in certificate record");
            }

            if (tags[1] != 1)
            {
                throw new InvalidTlvStructureException("Only one certificate must exist in certificate record");
            }
        }
    }
}