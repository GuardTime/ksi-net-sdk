using System;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    internal class PublicationsFileDo : CompositeTag
    {
        public PublicationsFileHeader PublicationsHeader { get; }
        public List<CertificateRecord> CertificateRecords { get; }
        public List<PublicationRecord> PublicationRecords { get; }
        public TlvTag CmsSignature { get; private set; }

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
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x701:
                        PublicationsHeader = new PublicationsFileHeader(Value[i]);
                        Value[i] = PublicationsHeader;
                        break;
                    case 0x702:
                        if (CertificateRecords == null)
                        {
                            CertificateRecords = new List<CertificateRecord>();
                        }

                        var certificateRecordTag = new CertificateRecord(Value[i]);
                        CertificateRecords.Add(certificateRecordTag);
                        Value[i] = certificateRecordTag;
                        break;
                    case 0x703:
                        if (PublicationRecords == null)
                        {
                            PublicationRecords = new List<PublicationRecord>();
                        }

                        var publicationRecordTag = new PublicationRecord(Value[i]);
                        PublicationRecords.Add(publicationRecordTag);
                        Value[i] = publicationRecordTag;
                        break;
                    case 0x704:
                        CmsSignature = Value[i];
                        break;
                    default:
                        // TODO: throw correct exception, also display invalid row in full tree
                        if (!Value[i].NonCritical)
                        {
                            throw new FormatException("Invalid tag[" + Value[i].Type + "]: " + this);
                        }
                        break;
                }
            }
        }

        public override bool IsValidStructure()
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

            return true;
        }
    }
}
