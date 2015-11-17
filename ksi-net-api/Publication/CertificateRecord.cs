using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Certificate record TLV element.
    /// </summary>
    public sealed class CertificateRecord : CompositeTag
    {
        private readonly RawTag _certificateId;
        private readonly RawTag _x509Certificate;

        /// <summary>
        ///     Create new certificate record TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public CertificateRecord(TlvTag tag) : base(tag)
        {
            if (Type != Constants.CertificateRecord.TagType)
            {
                throw new TlvException("Invalid certificate record type(" + Type + ").");
            }

            int certificateIdCount = 0;
            int x509CertificateCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case Constants.CertificateRecord.CertificateIdTagType:
                        _certificateId = new RawTag(this[i]);
                        certificateIdCount++;
                        break;
                    case Constants.CertificateRecord.X509CertificateTagType:
                        _x509Certificate = new RawTag(this[i]);
                        x509CertificateCount++;
                        break;
                    default:
                        VerifyUnknownTag(this[i]);
                        break;
                }
            }

            if (certificateIdCount != 1)
            {
                throw new TlvException("Only one certificate id must exist in certificate record.");
            }

            if (x509CertificateCount != 1)
            {
                throw new TlvException("Only one certificate must exist in certificate record.");
            }
        }

        /// <summary>
        ///     Get certificate ID.
        /// </summary>
        public RawTag CertificateId
        {
            get { return _certificateId; }
        }

        /// <summary>
        ///     Get X509 certificate.
        /// </summary>
        public RawTag X509Certificate
        {
            get { return _x509Certificate; }
        }
    }
}