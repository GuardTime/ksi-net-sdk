using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
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
        /// Get KSI trust provider name.
        /// </summary>
        public string Name
        {
            get { return "publications file"; }
        }

        /// <summary>
        /// Get publications file creation time.
        /// </summary>
        public ulong CreationTime
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
        /// Create publications file instance from data stream and default buffer size.
        /// </summary>
        /// <param name="stream">data stream</param>
        /// <returns>publications file</returns>
        public static PublicationsFile GetInstance(Stream stream)
        {
            return GetInstance(stream, 8092);
        }

        /// <summary>
        /// Create publications file instance from data stream and set buffer size.
        /// </summary>
        /// <param name="stream">data stream</param>
        /// <param name="bufferSize">buffer size</param>
        /// <returns>publications file</returns>
        public static PublicationsFile GetInstance(Stream stream, int bufferSize)
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

            using (MemoryStream memoryStream = new MemoryStream())
            {
                byte[] buffer = new byte[bufferSize];
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
            ReadOnlyCollection<PublicationRecord> publicationRecordCollection = _publicationsFileDo.GetPublicationRecords();

            int publicationRecordCount = publicationRecordCollection.Count;
            if (publicationRecordCount == 0)
            {
                return null;
            }

            PublicationRecord latest = null;
            for (int i = 0; i < publicationRecordCount; i++)
            {
                if (latest == null)
                {
                    latest = publicationRecordCollection[i];
                    continue;
                }

                if (publicationRecordCollection[i].PublicationData.PublicationTime.CompareTo(latest.PublicationData.PublicationTime) > 0)
                {
                    latest = publicationRecordCollection[i];
                }
            }

            return latest;
        }

        /// <summary>
        /// Get neared publication record to time.
        /// </summary>
        /// <param name="time">publication time</param>
        /// <returns>publication record closest to time</returns>
        public PublicationRecord GetNearestPublicationRecord(ulong time)
        {
            PublicationRecord nearestPublicationRecord = null;
            ReadOnlyCollection<PublicationRecord> publicationRecords = _publicationsFileDo.GetPublicationRecords();
            for (int i = 0; i < publicationRecords.Count; i++)
            {
                ulong publicationTime = publicationRecords[i].PublicationData.PublicationTime;
                if (publicationTime != time && publicationTime <= time) continue;

                if (nearestPublicationRecord == null)
                {
                    nearestPublicationRecord = publicationRecords[i];
                }
                else if (publicationTime < nearestPublicationRecord.PublicationData.PublicationTime)
                {
                    nearestPublicationRecord = publicationRecords[i];
                }
            }

            return nearestPublicationRecord;
        }

        

        /// <summary>
        /// Is publication record in publications file.
        /// </summary>
        /// <param name="publicationRecord">lookup publication record</param>
        /// <returns>true if publication record is in publications file</returns>
        public bool Contains(PublicationRecord publicationRecord)
        {
            if (publicationRecord == null)
            {
                return false;
            }

            ReadOnlyCollection<PublicationRecord> publicationRecordCollection = _publicationsFileDo.GetPublicationRecords();

            for (int i = 0; i < publicationRecordCollection.Count; i++)
            {
                if (publicationRecordCollection[i].PublicationData == null) continue;

                if (publicationRecordCollection[i].PublicationData.Equals(publicationRecord.PublicationData))
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
        public X509Certificate2 FindCertificateById(byte[] certificateId)
        {
            ReadOnlyCollection<CertificateRecord> certificateRecordCollection = _publicationsFileDo.GetCertificateRecords();

            for (int i = 0; i < certificateRecordCollection.Count; i++)
            {
                if (Util.IsArrayEqual(certificateRecordCollection[i].CertificateId.EncodeValue(),
                    certificateId))
                {
                    return new X509Certificate2(certificateRecordCollection[i].X509Certificate.EncodeValue());
                }
            }
            return null;
        }

        /// <summary>
        /// Get signed bytes.
        /// </summary>
        /// <returns>signed bytes</returns>
        public byte[] GetSignatureBytes()
        {
            return _publicationsFileDo.CmsSignature.EncodeValue();
        }

        /// <summary>
        /// Get signature bytes.
        /// </summary>
        /// <returns>signature bytes</returns>
        public byte[] GetSignedBytes()
        {
            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.Write(FileBeginningMagicBytes);
                for (int i = 0; i < _publicationsFileDo.Count - 1; i++)
                {
                    writer.WriteTag(_publicationsFileDo[i]);
                }
                return stream.ToArray();
            }
        }

        /// <summary>
        /// Get publications data object as string.
        /// </summary>
        /// <returns>publications file data object string</returns>
        public string GetDataObjectAsString()
        {
            return _publicationsFileDo.ToString();
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

            PublicationRecord latestPublication = GetLatestPublication();
            if (latestPublication != null)
            {
                builder.Append(", last publication: ").Append(latestPublication.PublicationData.PublicationTime);
            }
            
            if (RepUri != null)
            {
                builder.Append(", published at: ").Append(RepUri);
            }

            return builder.ToString();
        }
    }
}
