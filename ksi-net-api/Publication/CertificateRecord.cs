using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Certificate record TLV element.
    /// </summary>
    public sealed class CertificateRecord : CompositeTag
    {
        /// <summary>
        ///     Create new certificate record TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        
        public CertificateRecord(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.CertificateRecord.TagType)
            {
                throw new TlvException("Invalid certificate record type(" + Type + ").");
            }

            int certificateIdCount = 0;
            int x509CertificateCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.CertificateRecord.CertificateIdTagType:
                        CertificateId = new RawTag(childTag);
                        certificateIdCount++;
                        break;
                    case Constants.CertificateRecord.X509CertificateTagType:
                        X509Certificate = new RawTag(childTag);
                        x509CertificateCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
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
        public RawTag CertificateId { get; }

        /// <summary>
        ///     Get X509 certificate.
        /// </summary>
        public RawTag X509Certificate { get; }
    }
}