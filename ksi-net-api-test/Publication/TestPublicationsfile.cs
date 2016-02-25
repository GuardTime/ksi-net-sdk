using System.Collections.Generic;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Publication
{
    public class TestPublicationsFile : IPublicationsFile
    {
        public uint Type => 0;
        public bool NonCritical => false;
        public bool Forward => false;

        public byte[] EncodeValueBytes;

        public List<PublicationRecordInPublicationFile> PublicationRecords = new List<PublicationRecordInPublicationFile>();

        public List<CertificateRecord> CertificateRecords = new List<CertificateRecord>();

        public Dictionary<ulong, PublicationRecordInPublicationFile> NearestPublications = new Dictionary<ulong, PublicationRecordInPublicationFile>();
        public PublicationRecordInPublicationFile LatestPublication;

        public byte[] EncodeValue()
        {
            return EncodeValueBytes;
        }

        public bool Contains(PublicationRecord publicationRecord)
        {
            if (publicationRecord == null)
            {
                return false;
            }

            foreach (PublicationRecordInPublicationFile record in PublicationRecords)
            {
                if (record.PublicationData.PublicationTime == publicationRecord.PublicationData.PublicationTime &&
                    record.PublicationData.PublicationHash == publicationRecord.PublicationData.PublicationHash)
                {
                    return true;
                }
            }

            return false;
        }

        public byte[] FindCertificateById(byte[] certificateId)
        {
            foreach (CertificateRecord certificateRecord in CertificateRecords)
            {
                if (Util.IsArrayEqual(certificateRecord.CertificateId.EncodeValue(), certificateId))
                {
                    return certificateRecord.X509Certificate.EncodeValue();
                }
            }

            return null;
        }

        public PublicationRecordInPublicationFile GetNearestPublicationRecord(ulong time)
        {
            return NearestPublications.ContainsKey(time) ? NearestPublications[time] : null;
        }

        public PublicationRecordInPublicationFile GetLatestPublication()
        {
            return LatestPublication;
        }
    }
}