using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Trust;

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

        public string Name { get; }

        private PublicationsFile(PublicationsFileDo publicationFileDo)
        {
            if (publicationFileDo == null)
            {
                throw new ArgumentNullException(nameof(publicationFileDo));
            }

            _publicationsFileDo = publicationFileDo;
        }

        public static PublicationsFile GetInstance(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            return GetInstance(new MemoryStream(bytes));
        }

        public static PublicationsFile GetInstance(Stream stream)
        {
            // TODO: Java api check if stream is null
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            var data = new byte[FileBeginningMagicBytes.Length];
            var bytesRead = stream.Read(data, 0, data.Length);

            if (bytesRead != FileBeginningMagicBytes.Length || !Util.Util.IsArrayEqual(data, FileBeginningMagicBytes))
            {
                stream.Close();
                // TODO: Correct exception
                throw new KsiException("Invalid publications file: incorrect file header");
            }

            // TODO: Check for too long file
            data = new byte[stream.Length - 8];
            stream.Read(data, 0, data.Length);
            stream.Close();

            return new PublicationsFile(new PublicationsFileDo(new RawTag(0x0, false, false, data)));
        }

        public PublicationRecord GetLatestPublication()
        {
            var publicationRecordCount = _publicationsFileDo.PublicationRecords.Count;
            if (publicationRecordCount == 0)
            {
                return null;
            }

            PublicationRecord latest = null;
            for (var i = 0; i < publicationRecordCount; i++)
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

            for (var i = 0; i < _publicationsFileDo.PublicationRecords.Count; i++)
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
            for (var i = 0; i < _publicationsFileDo.CertificateRecords.Count; i++)
            {
                if (Util.Util.IsArrayEqual(_publicationsFileDo.CertificateRecords[i].CertificateId.EncodeValue(),
                    certificateId))
                {
                    return new X509Certificate(_publicationsFileDo.CertificateRecords[i].X509Certificate.EncodeValue());
                }
            }
            return null;
        }

        

        public override string ToString()
        {
            var builder = new StringBuilder();
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
