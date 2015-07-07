using System;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    internal class PublicationsFileDo : CompositeTag
    {
        // TODO: Better name, const?
        private const uint CmsSignatureTagType = 0x704;

        private readonly PublicationsFileHeader _publicationsHeader;
        private readonly List<CertificateRecord> _certificateRecords = new List<CertificateRecord>();
        private readonly List<PublicationRecord> _publicationRecords = new List<PublicationRecord>();
        private readonly TlvTag _cmsSignature;

        public PublicationsFileHeader PublicationsHeader
        {
            get { return _publicationsHeader; }
        }

        public List<CertificateRecord> CertificateRecords
        {
            get { return _certificateRecords; }
        }

        public List<PublicationRecord> PublicationRecords
        {
            get { return _publicationRecords; }
        }

        public TlvTag CmsSignature
        {
            get { return _cmsSignature; }
        }

        public DateTime? CreationTime
        {
            get { return _publicationsHeader.CreationTime; }
        }

        public string RepUri
        {
            get { return _publicationsHeader.RepUri; }
        }

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
                    case PublicationRecord.TagType:
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
                    case PublicationRecord.TagType:
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
