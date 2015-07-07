using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Publication
{
    public sealed class PublicationsFile : IKsiTrustProvider
    {
        public static readonly byte[] FileBeginningMagicBytes = { 0x4b, 0x53, 0x49, 0x50, 0x55, 0x42, 0x4c, 0x46 };
        private readonly PublicationsFileDo _publicationsFileDo;

        // TODO: Problem with too big value
        public DateTime? CreationTime
        {
            get { return _publicationsFileDo.CreationTime; }
        }

        public string RepUri
        {
            get { return _publicationsFileDo.RepUri; }
        }

        private PublicationsFile(PublicationsFileDo publicationFileDo)
        {
            if (publicationFileDo == null)
            {
                throw new ArgumentNullException("publicationFileDo");
            }

            _publicationsFileDo = publicationFileDo;
        }

        public static PublicationsFile GetInstance(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            return GetInstance(new MemoryStream(bytes));
        }

        public static PublicationsFile GetInstance(Stream stream)
        {
            // TODO: Java api check if stream is null
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            byte[] data = new byte[FileBeginningMagicBytes.Length];
            int bytesRead = stream.Read(data, 0, data.Length);

            if (bytesRead != FileBeginningMagicBytes.Length || !Util.IsArrayEqual(data, FileBeginningMagicBytes))
            {
                // TODO: Correct exception
                throw new KsiException("Invalid publications file: incorrect file header");
            }

            // TODO: Check for too long file
            using (MemoryStream memoryStream = new MemoryStream())
            {
                // TODO: Make buffer configurable
                byte[] buffer = new byte[8092];
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    memoryStream.Write(buffer, 0, bytesRead);
                }

                return new PublicationsFile(new PublicationsFileDo(new RawTag(0x0, false, false, memoryStream.ToArray())));
            }
        }

        public PublicationRecord GetLatestPublication()
        {
            int publicationRecordCount = _publicationsFileDo.PublicationRecords.Count;
            if (publicationRecordCount == 0)
            {
                return null;
            }

            PublicationRecord latest = null;
            for (int i = 0; i < publicationRecordCount; i++)
            {
                if (latest == null)
                {
                    latest = _publicationsFileDo.PublicationRecords[i];
                    continue;
                }

                if (_publicationsFileDo.PublicationRecords[i].PublicationTime.CompareTo(latest.PublicationTime) > 0)
                {
                    latest = _publicationsFileDo.PublicationRecords[i];
                }
            }

            return latest;
        }

        public bool Contains(PublicationRecord publicationRecord)
        {
            if (publicationRecord == null) return false;

            for (int i = 0; i < _publicationsFileDo.PublicationRecords.Count; i++)
            {
                if (_publicationsFileDo.PublicationRecords[i].PublicationData == null) continue;

                if (
                    _publicationsFileDo.PublicationRecords[i].PublicationData.Equals(
                        publicationRecord.PublicationData))
                {
                    return true;
                }
            }


            return false;
        }

        public X509Certificate FindCertificateById(byte[] certificateId)
        {
            for (int i = 0; i < _publicationsFileDo.CertificateRecords.Count; i++)
            {
                if (Util.IsArrayEqual(_publicationsFileDo.CertificateRecords[i].CertificateId.EncodeValue(),
                    certificateId))
                {
                    return new X509Certificate(_publicationsFileDo.CertificateRecords[i].X509Certificate.EncodeValue());
                }
            }
            return null;
        }

        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("Publications file");

            builder.Append(", created: ").Append(CreationTime);
            // TODO: Check if publication always exists
            builder.Append(", last publication: ").Append(GetLatestPublication().PublicationTime);
            if (RepUri != null)
            {
                builder.Append(", published at: ").Append(RepUri);
            }

            return builder.ToString();
        }
    }
}
