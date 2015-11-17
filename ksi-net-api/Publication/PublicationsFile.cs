using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Publication
{
    public partial class PublicationsFileFactory
    {
        /// <summary>
        ///     Publications file implementation.
        /// </summary>
        private sealed class PublicationsFile : CompositeTag, IPublicationsFile
        {
            /// <summary>
            ///     Publications file beginning bytes "KSIPUBLF".
            /// </summary>
            public static readonly byte[] FileBeginningMagicBytes = {0x4b, 0x53, 0x49, 0x50, 0x55, 0x42, 0x4c, 0x46};

            private readonly List<CertificateRecord> _certificateRecordList = new List<CertificateRecord>();
            private readonly RawTag _cmsSignature;
            private readonly List<PublicationRecord> _publicationRecordList = new List<PublicationRecord>();
            private readonly PublicationsFileHeader _publicationsHeader;

            /// <summary>
            ///     Create new publications file TLV element from TLV element.
            /// </summary>
            /// <param name="tag">TLV element</param>
            /// <exception cref="PublicationsFileException">thrown when TLV parsing fails</exception>
            public PublicationsFile(ITlvTag tag) : base(tag)
            {
                int publicationsHeaderCount = 0;
                int cmsSignatureCount = 0;

                for (int i = 0; i < Count; i++)
                {
                    switch (this[i].Type)
                    {
                        case Constants.PublicationsFileHeader.TagType:
                            _publicationsHeader = new PublicationsFileHeader(this[i]);
                            publicationsHeaderCount++;
                            if (i != 0)
                            {
                                throw new PublicationsFileException(
                                    "Publications file header should be the first element in publications file.");
                            }
                            break;
                        case Constants.CertificateRecord.TagType:
                            CertificateRecord certificateRecordTag = new CertificateRecord(this[i]);
                            _certificateRecordList.Add(certificateRecordTag);
                            if (_publicationRecordList.Count != 0)
                            {
                                throw new PublicationsFileException(
                                    "Certificate records should be before publication records.");
                            }
                            break;
                        case Constants.PublicationRecord.TagTypePublication:
                            PublicationRecord publicationRecordTag = new PublicationRecord(this[i]);
                            _publicationRecordList.Add(publicationRecordTag);
                            break;
                        case Constants.PublicationsFile.CmsSignatureTagType:
                            _cmsSignature = new RawTag(this[i]);
                            cmsSignatureCount++;
                            if (i != Count - 1)
                            {
                                throw new PublicationsFileException(
                                    "Cms signature should be last element in publications file.");
                            }
                            break;
                        default:
                            VerifyCriticalFlag(this[i]);
                            break;
                    }
                }

                if (publicationsHeaderCount != 1)
                {
                    throw new PublicationsFileException(
                        "Only one publications file header must exist in publications file.");
                }

                if (cmsSignatureCount != 1)
                {
                    throw new PublicationsFileException("Only one signature must exist in publications file.");
                }
            }

            /// <summary>
            ///     Get KSI trust provider name.
            /// </summary>
            public string Name
            {
                get { return "publications file"; }
            }

            /// <summary>
            ///     Get latest publication record.
            /// </summary>
            /// <returns>publication record</returns>
            public PublicationRecord GetLatestPublication()
            {
                PublicationRecord latest = null;
                for (int i = 0; i < _publicationRecordList.Count; i++)
                {
                    if (latest == null)
                    {
                        latest = _publicationRecordList[i];
                        continue;
                    }

                    if (
                        _publicationRecordList[i].PublicationData.PublicationTime.CompareTo(
                            latest.PublicationData.PublicationTime) > 0)
                    {
                        latest = _publicationRecordList[i];
                    }
                }

                return latest;
            }

            /// <summary>
            ///     Get neared publication record to time.
            /// </summary>
            /// <param name="time">publication time</param>
            /// <returns>publication record closest to time</returns>
            public PublicationRecord GetNearestPublicationRecord(ulong time)
            {
                PublicationRecord nearestPublicationRecord = null;
                for (int i = 0; i < _publicationRecordList.Count; i++)
                {
                    ulong publicationTime = _publicationRecordList[i].PublicationData.PublicationTime;
                    if (publicationTime != time && publicationTime <= time)
                    {
                        continue;
                    }

                    if (nearestPublicationRecord == null)
                    {
                        nearestPublicationRecord = _publicationRecordList[i];
                    }
                    else if (publicationTime < nearestPublicationRecord.PublicationData.PublicationTime)
                    {
                        nearestPublicationRecord = _publicationRecordList[i];
                    }
                }

                return nearestPublicationRecord;
            }

            /// <summary>
            ///     Is publication record in publications file.
            /// </summary>
            /// <param name="publicationRecord">lookup publication record</param>
            /// <returns>true if publication record is in publications file</returns>
            public bool Contains(PublicationRecord publicationRecord)
            {
                if (publicationRecord == null)
                {
                    return false;
                }

                for (int i = 0; i < _publicationRecordList.Count; i++)
                {
                    if (_publicationRecordList[i].PublicationData.PublicationTime ==
                        publicationRecord.PublicationData.PublicationTime &&
                        _publicationRecordList[i].PublicationData.PublicationHash ==
                        publicationRecord.PublicationData.PublicationHash)
                    {
                        return true;
                    }
                }

                return false;
            }

            /// <summary>
            ///     Get certificate by certificate ID.
            /// </summary>
            /// <param name="certificateId">certificate id</param>
            /// <returns>X509 certificate</returns>
            public X509Certificate2 FindCertificateById(byte[] certificateId)
            {
                for (int i = 0; i < _certificateRecordList.Count; i++)
                {
                    if (Util.IsArrayEqual(_certificateRecordList[i].CertificateId.EncodeValue(),
                        certificateId))
                    {
                        return new X509Certificate2(_certificateRecordList[i].X509Certificate.EncodeValue());
                    }
                }
                return null;
            }

            /// <summary>
            ///     Get signed bytes.
            /// </summary>
            /// <returns>signed bytes</returns>
            public byte[] GetSignatureBytes()
            {
                return _cmsSignature.EncodeValue();
            }

            /// <summary>
            ///     Get signature bytes.
            /// </summary>
            /// <returns>signature bytes</returns>
            public byte[] GetSignedBytes()
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.Write(FileBeginningMagicBytes);
                    for (int i = 0; i < Count - 1; i++)
                    {
                        writer.WriteTag(this[i]);
                    }
                    return ((MemoryStream)writer.BaseStream).ToArray();
                }
            }

            /// <summary>
            ///     Convert publications file to string.
            /// </summary>
            /// <returns>publications file as string</returns>
            public override string ToString()
            {
                StringBuilder builder = new StringBuilder();
                builder.Append("Publications file");

                builder.Append(", created: ").Append(_publicationsHeader.CreationTime);

                PublicationRecord latestPublication = GetLatestPublication();
                if (latestPublication != null)
                {
                    builder.Append(", last publication: ").Append(latestPublication.PublicationData.PublicationTime);
                }

                if (_publicationsHeader.RepUri != null)
                {
                    builder.Append(", published at: ").Append(_publicationsHeader.RepUri);
                }

                return builder.ToString();
            }
        }
    }
}