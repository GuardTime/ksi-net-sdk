using System;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    /// Publications file TLV element
    /// </summary>
    public sealed class PublicationsFileDo : CompositeTag
    {
        private const uint CmsSignatureTagType = 0x704;

        private readonly PublicationsFileHeader _publicationsHeader;
        private readonly List<CertificateRecord> _certificateRecords = new List<CertificateRecord>();
        private readonly List<PublicationRecord> _publicationRecords = new List<PublicationRecord>();
        private readonly TlvTag _cmsSignature;

        /// <summary>
        /// Get publications file header
        /// </summary>
        public PublicationsFileHeader PublicationsHeader
        {
            get { return _publicationsHeader; }
        }

        /// <summary>
        /// Get certificate records
        /// </summary>
        public List<CertificateRecord> CertificateRecords
        {
            get { return _certificateRecords; }
        }

        /// <summary>
        /// Get publication records
        /// </summary>
        public List<PublicationRecord> PublicationRecords
        {
            get { return _publicationRecords; }
        }

        /// <summary>
        /// Get cms signature
        /// </summary>
        public TlvTag CmsSignature
        {
            get { return _cmsSignature; }
        }

        /// <summary>
        /// Get creation time
        /// </summary>
        public DateTime? CreationTime
        {
            get { return _publicationsHeader.CreationTime; }
        }

        /// <summary>
        /// Get repository uri
        /// </summary>
        public string RepUri
        {
            get { return _publicationsHeader.RepUri; }
        }

        /// <summary>
        /// Create new publications file TLV element from TLV element
        /// </summary>
        /// <param name="tagList">TLV tag list</param>
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
                        break;
                    case CertificateRecord.TagType:
                        CertificateRecord certificateRecordTag = new CertificateRecord(this[i]);
                        CertificateRecords.Add(certificateRecordTag);
                        this[i] = certificateRecordTag;
                        break;
                    case PublicationRecord.TagTypePublication:
                        PublicationRecord publicationRecordTag = new PublicationRecord(this[i]);
                        PublicationRecords.Add(publicationRecordTag);
                        this[i] = publicationRecordTag;
                        break;
                    case CmsSignatureTagType:
                        _cmsSignature = this[i];
                        cmsSignatureCount++;
                        break;
                    default:
                        VerifyCriticalTag(this[i]);
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

    }
}
