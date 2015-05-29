using System;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    internal class PublicationsFileDo : CompositeTag
    {
        private PublicationsFileHeader _publicationsHeader;
        private List<CertificateRecord> _certificateRecords;
        private List<PublicationRecord> _publicationRecords;
        private TlvTag _cmsSignature;

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
            get { return PublicationsHeader.CreationTime != null ? Util.Util.ConvertUnixTimeToDateTime(PublicationsHeader.CreationTime.Value / 1000) : (DateTime?) null; }
        }

        public string RepUri
        {
            get { return PublicationsHeader.RepUri != null ? PublicationsHeader.RepUri.Value : null; }
        }

        public PublicationsFileDo(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case 0x701:
                        _publicationsHeader = new PublicationsFileHeader(this[i]);
                        this[i] = _publicationsHeader;
                        break;
                    case 0x702:
                        if (_certificateRecords == null)
                        {
                            _certificateRecords = new List<CertificateRecord>();
                        }

                        CertificateRecord certificateRecordTag = new CertificateRecord(this[i]);
                        CertificateRecords.Add(certificateRecordTag);
                        this[i] = certificateRecordTag;
                        break;
                    case 0x703:
                        if (_publicationRecords == null)
                        {
                            _publicationRecords = new List<PublicationRecord>();
                        }

                        PublicationRecord publicationRecordTag = new PublicationRecord(this[i]);
                        PublicationRecords.Add(publicationRecordTag);
                        this[i] = publicationRecordTag;
                        break;
                    case 0x704:
                        _cmsSignature = this[i];
                        break;
                    default:
                        // TODO: throw correct exception, also display invalid row in full tree
                        if (!this[i].NonCritical)
                        {
                            throw new FormatException("Invalid tag[" + this[i].Type + "]: " + this);
                        }
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            if (PublicationsHeader == null)
            {
                throw new InvalidTlvStructureException("Publications File Header is missing");
            }

            if (CertificateRecords == null || CertificateRecords.Count == 0)
            {
                throw new InvalidTlvStructureException("Certificate records are missing");
            }

            if (PublicationRecords == null || PublicationRecords.Count == 0)
            {
                throw new InvalidTlvStructureException("Publication records are missing");
            }

            if (CmsSignature == null)
            {
                throw new InvalidTlvStructureException("Publication file signature is missing");
            }
        }
    }
}
