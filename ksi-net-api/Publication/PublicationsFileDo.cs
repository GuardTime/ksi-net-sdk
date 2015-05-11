using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
//    public class PublicationsFileDo : CompositeTag
//    {
//        private PublicationFileHeader _publicationHeader;
//
//        private List<CertificateRecord> _certificateRecords;
//
//        private List<PublicationRecord> _publicationRecords;
//
//        private RawTag _cmsSignature;
//
//        public PublicationsFileDo(ITlvTag tag) : base(tag)
//        {
//        }
//
//        public override ITlvTag GetMember(ITlvTag tag)
//        {
//            switch (tag.Type)
//            {
//                case 0x701:
//                    _publicationHeader = new PublicationFileHeader(tag);
//                    return _publicationHeader;
//                case 0x702:
//                    if (_certificateRecords == null)
//                    {
//                        _certificateRecords = new List<CertificateRecord>();
//                    }
//
//                    var certificateRecordTag = new CertificateRecord(tag);
//                    _certificateRecords.Add(certificateRecordTag);
//                    return certificateRecordTag;
//                case 0x703:
//                    if (_publicationRecords == null)
//                    {
//                        _publicationRecords = new List<PublicationRecord>();
//                    }
//
//                    var publicationRecordTag = new PublicationRecord(tag);
//                    _publicationRecords.Add(publicationRecordTag);
//                    return publicationRecordTag;
//                case 0x704:
//                    _cmsSignature = new RawTag(tag);
//                    return _cmsSignature;
//            }
//
//            return null;
//        }

        
//    }
}
