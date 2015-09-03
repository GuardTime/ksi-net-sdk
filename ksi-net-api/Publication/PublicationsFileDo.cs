using System.Collections.Generic;
using System.Collections.ObjectModel;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    /// Publications file TLV element.
    /// </summary>
    public sealed class PublicationsFileDo : CompositeTag
    {
        private const uint CmsSignatureTagType = 0x704;

        private readonly PublicationsFileHeader _publicationsHeader;
        private readonly List<CertificateRecord> _certificateRecordList = new List<CertificateRecord>();
        private readonly List<PublicationRecord> _publicationRecordList = new List<PublicationRecord>();
        private readonly TlvTag _cmsSignature;

        /// <summary>
        /// Get publications file header.
        /// </summary>
        public PublicationsFileHeader PublicationsHeader
        {
            get { return _publicationsHeader; }
        }

        /// <summary>
        /// Get cms signature.
        /// </summary>
        public TlvTag CmsSignature
        {
            get { return _cmsSignature; }
        }

        /// <summary>
        /// Get creation time.
        /// </summary>
        public ulong CreationTime
        {
            get { return _publicationsHeader.CreationTime; }
        }

        /// <summary>
        /// Get repository uri.
        /// </summary>
        public string RepUri
        {
            get { return _publicationsHeader.RepUri; }
        }

        /// <summary>
        /// Create new publications file TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public PublicationsFileDo(TlvTag tag) : base(tag)
        {
            int publicationsHeaderCount = 0;
            int cmsSignatureCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationsFileHeader.TagType:
                        _publicationsHeader = new PublicationsFileHeader(this[i]);
                        this[i] = _publicationsHeader;
                        publicationsHeaderCount++;
                        if (i != 0)
                        {
                            throw new InvalidTlvStructureException("Publications file header should be the first element in publications file");
                        }
                        break;
                    case CertificateRecord.TagType:
                        CertificateRecord certificateRecordTag = new CertificateRecord(this[i]);
                        _certificateRecordList.Add(certificateRecordTag);
                        this[i] = certificateRecordTag;
                        if (_publicationRecordList.Count != 0)
                        {
                            throw new InvalidTlvStructureException("Certificate records should be before publication records");
                        }
                        break;
                    case PublicationRecord.TagTypePublication:
                        PublicationRecord publicationRecordTag = new PublicationRecord(this[i]);
                        _publicationRecordList.Add(publicationRecordTag);
                        this[i] = publicationRecordTag;
                        break;
                    case CmsSignatureTagType:
                        _cmsSignature = this[i];
                        cmsSignatureCount++;
                        if (i != Count - 1)
                        {
                            throw new InvalidTlvStructureException("Cms signature should be last element in publications file");
                        }
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (publicationsHeaderCount != 1)
            {
                throw new InvalidTlvStructureException("Only one publications file header must exist in publications file");
            }

            if (cmsSignatureCount != 1)
            {
                throw new InvalidTlvStructureException("Only one signature must exist in publications file");
            }
        }

        /// <summary>
        /// Get certificate records.
        /// </summary>
        public ReadOnlyCollection<CertificateRecord> GetCertificateRecords()
        {
            return _certificateRecordList.AsReadOnly();
        }

        /// <summary>
        /// Get publication records.
        /// </summary>
        public ReadOnlyCollection<PublicationRecord> GetPublicationRecords()
        {
            return _publicationRecordList.AsReadOnly();
        }

    }
}
