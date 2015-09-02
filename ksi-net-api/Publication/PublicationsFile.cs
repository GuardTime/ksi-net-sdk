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
    /// <summary>
    /// Publication file.
    /// </summary>
    public sealed class PublicationsFile : IKsiTrustProvider
    {
        /// <summary>
        /// Publications file beginning bytes "KSIPUBLF". 
        /// </summary>
        public static readonly byte[] FileBeginningMagicBytes = { 0x4b, 0x53, 0x49, 0x50, 0x55, 0x42, 0x4c, 0x46 };
        private readonly PublicationsFileDo _publicationsFileDo;

        /// <summary>
        /// Get publications file creation time.
        /// </summary>
        // TODO: Problem with too big value
        public DateTime? CreationTime
        {
            get { return _publicationsFileDo.CreationTime; }
        }

        /// <summary>
        /// Get publications file repository uri.
        /// </summary>
        public string RepUri
        {
            get { return _publicationsFileDo.RepUri; }
        }

        /// <summary>
        /// Create publications file instance from publications file data object.
        /// </summary>
        /// <param name="publicationFileDo">Publications file data object</param>
        private PublicationsFile(PublicationsFileDo publicationFileDo)
        {
            if (publicationFileDo == null)
            {
                throw new ArgumentNullException("publicationFileDo");
            }

            _publicationsFileDo = publicationFileDo;
        }

        /// <summary>
        /// Create publications file instance from data bytes.
        /// </summary>
        /// <param name="bytes">data bytes</param>
        /// <returns>publications file</returns>
        public static PublicationsFile GetInstance(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            return GetInstance(new MemoryStream(bytes));
        }

        /// <summary>
        /// Create publications file instance from data stream.
        /// </summary>
        /// <param name="stream">data stream</param>
        /// <returns>publications file</returns>
        public static PublicationsFile GetInstance(Stream stream)
        {
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

        /// <summary>
        /// Get latest publication record.
        /// </summary>
        /// <returns>publication record</returns>
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

                if (_publicationsFileDo.PublicationRecords[i].PublicationData.PublicationTime.Value.CompareTo(latest.PublicationData.PublicationTime.Value) > 0)
                {
                    latest = _publicationsFileDo.PublicationRecords[i];
                }
            }

            return latest;
        }

        /// <summary>
        /// Is publication record in publications file.
        /// </summary>
        /// <param name="publicationRecord">lookup publication record</param>
        /// <returns>true if publication record is in publications file</returns>
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

        /// <summary>
        /// Get certificate by certificate ID.
        /// </summary>
        /// <param name="certificateId">certificate id</param>
        /// <returns>X509 certificate</returns>
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

        /// <summary>
        /// Convert publications file to string.
        /// </summary>
        /// <returns>publications file as string</returns>
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("Publications file");

            builder.Append(", created: ").Append(CreationTime);
            // TODO: Check if publication always exists
            builder.Append(", last publication: ").Append(GetLatestPublication().PublicationData.PublicationTime.Value);
            if (RepUri != null)
            {
                builder.Append(", published at: ").Append(RepUri);
            }

            return builder.ToString();
        }
    }
}
