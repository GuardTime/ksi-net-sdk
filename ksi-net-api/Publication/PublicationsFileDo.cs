using System;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    /// Publications file TLV element
    /// </summary>
    internal class PublicationsFileDo : CompositeTag
    {
        public const uint PublicationRecordTagType = 0x703;
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
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationsFileHeader.TagType:
                        _publicationsHeader = new PublicationsFileHeader(this[i]);
                        this[i] = _publicationsHeader;
                        break;
                    case CertificateRecord.TagType:
                        CertificateRecord certificateRecordTag = new CertificateRecord(this[i]);
                        CertificateRecords.Add(certificateRecordTag);
                        this[i] = certificateRecordTag;
                        break;
                    case PublicationRecordTagType:
                        PublicationRecord publicationRecordTag = new PublicationRecord(this[i]);
                        PublicationRecords.Add(publicationRecordTag);
                        this[i] = publicationRecordTag;
                        break;
                    case CmsSignatureTagType:
                        _cmsSignature = this[i];
                        break;
                }
            }
        }

        /// <summary>
        /// Check TLV structure.
        /// </summary>
        protected override void CheckStructure()
        {
            uint[] tags = new uint[4];

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationsFileHeader.TagType:
                        tags[0]++;
                        break;
                    case CertificateRecord.TagType:
                        tags[1]++;
                        break;
                    case PublicationRecordTagType:
                        tags[2]++;
                        break;
                    case CmsSignatureTagType:
                        tags[3]++;
                        break;
                    default:
                        throw new InvalidTlvStructureException("Invalid tag", this[i]);
                }
            }

            if (tags[0] != 1)
            {
                throw new InvalidTlvStructureException("Only one publications file header must exist in publications file");
            }

            if (tags[3] != 1)
            {
                throw new InvalidTlvStructureException("Only one signature must exist in publications file");
            }
        }
    }
}
