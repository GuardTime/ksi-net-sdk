﻿/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publications file implementation.
    /// </summary>
    public sealed class PublicationsFile : CompositeTag, IPublicationsFile
    {
        /// <summary>
        ///     Publications file beginning bytes "KSIPUBLF".
        /// </summary>
        public static readonly byte[] FileBeginningMagicBytes = { 0x4b, 0x53, 0x49, 0x50, 0x55, 0x42, 0x4c, 0x46 };

        private readonly List<CertificateRecord> _certificateRecordList = new List<CertificateRecord>();
        private RawTag _cmsSignature;
        private readonly List<PublicationRecordInPublicationFile> _publicationRecordList = new List<PublicationRecordInPublicationFile>();
        private PublicationsFileHeader _publicationsHeader;
        private int _headerIndex;
        private int _lastCertRecordIndex;
        private int _firstPublicationRecordIndex;
        private int _cmsSignatureIndex;

        /// <summary>
        ///     Create new publications file TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public PublicationsFile(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.PublicationsFileHeader.TagType:
                    _headerIndex = Count;
                    return _publicationsHeader = childTag as PublicationsFileHeader ?? new PublicationsFileHeader(childTag);
                case Constants.CertificateRecord.TagType:
                    _lastCertRecordIndex = Count;
                    CertificateRecord certificateRecord = childTag as CertificateRecord ?? new CertificateRecord(childTag);
                    _certificateRecordList.Add(certificateRecord);
                    return certificateRecord;
                case Constants.PublicationRecord.TagTypeInPublicationsFile:
                    if (_firstPublicationRecordIndex == 0)
                    {
                        _firstPublicationRecordIndex = Count;
                    }
                    PublicationRecordInPublicationFile publicationRecord = childTag as PublicationRecordInPublicationFile ?? new PublicationRecordInPublicationFile(childTag);
                    _publicationRecordList.Add(publicationRecord);
                    return publicationRecord;
                case Constants.PublicationsFile.CmsSignatureTagType:
                    _cmsSignatureIndex = Count;
                    return _cmsSignature = GetRawTag(childTag);
                default:
                    return base.ParseChild(childTag);
            }
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate(TagCounter tagCounter)
        {
            base.Validate(tagCounter);

            if (_headerIndex != 0)
            {
                throw new PublicationsFileException("Publications file header should be the first element in publications file.");
            }

            if (_firstPublicationRecordIndex < _lastCertRecordIndex)
            {
                throw new PublicationsFileException("Certificate records should be before publication records.");
            }

            if (_cmsSignatureIndex != Count - 1)
            {
                throw new PublicationsFileException("Cms signature should be last element in publications file.");
            }

            if (tagCounter[Constants.PublicationsFileHeader.TagType] != 1)
            {
                throw new PublicationsFileException("Exactly one publications file header must exist in publications file.");
            }

            if (tagCounter[Constants.PublicationsFile.CmsSignatureTagType] != 1)
            {
                throw new PublicationsFileException("Exactly one signature must exist in publications file.");
            }
        }

        /// <summary>
        ///     Get latest publication record.
        /// </summary>
        /// <returns>publication record</returns>
        public PublicationRecordInPublicationFile GetLatestPublication()
        {
            PublicationRecordInPublicationFile latest = null;

            foreach (PublicationRecordInPublicationFile publicationRecord in _publicationRecordList)
            {
                if (latest == null)
                {
                    latest = publicationRecord;
                    continue;
                }

                if (publicationRecord.PublicationData.PublicationTime.CompareTo(latest.PublicationData.PublicationTime) > 0)
                {
                    latest = publicationRecord;
                }
            }

            return latest;
        }

        /// <summary>
        ///     Get nearest publication record subsequent to given time.
        /// </summary>
        /// <param name="time">time</param>
        /// <returns>publication record closest to time</returns>
        public PublicationRecordInPublicationFile GetNearestPublicationRecord(DateTime time)
        {
            return GetNearestPublicationRecord(Util.ConvertDateTimeToUnixTime(time));
        }

        /// <summary>
        ///     Get nearest publication record subsequent to given time.
        /// </summary>
        /// <param name="time">time</param>
        /// <returns>publication record closest to time</returns>
        public PublicationRecordInPublicationFile GetNearestPublicationRecord(ulong time)
        {
            PublicationRecordInPublicationFile nearestPublicationRecord = null;

            foreach (PublicationRecordInPublicationFile publicationRecord in _publicationRecordList)
            {
                ulong publicationTime = publicationRecord.PublicationData.PublicationTime;
                if (publicationTime < time)
                {
                    continue;
                }

                if (nearestPublicationRecord == null)
                {
                    nearestPublicationRecord = publicationRecord;
                }
                else if (publicationTime < nearestPublicationRecord.PublicationData.PublicationTime)
                {
                    nearestPublicationRecord = publicationRecord;
                }
            }

            return nearestPublicationRecord;
        }

        /// <summary>
        ///     Get certificate by certificate ID.
        /// </summary>
        /// <param name="certificateId">certificate id</param>
        /// <returns>X509 certificate</returns>
        public byte[] FindCertificateById(byte[] certificateId)
        {
            foreach (CertificateRecord certificateRecord in _certificateRecordList)
            {
                if (Util.IsArrayEqual(certificateRecord.CertificateId.EncodeValue(), certificateId))
                {
                    return certificateRecord.X509Certificate.EncodeValue();
                }
            }

            return null;
        }

        /// <summary>
        ///     Get signature
        /// </summary>
        /// <returns>signature bytes</returns>
        public byte[] GetSignatureValue()
        {
            return _cmsSignature.EncodeValue();
        }

        /// <summary>
        ///     Get signed bytes.
        /// </summary>
        /// <returns>signed bytes</returns>
        public byte[] GetSignedBytes()
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.Write(FileBeginningMagicBytes);

                // get all but last tag
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

            PublicationRecordInPublicationFile latestPublication = GetLatestPublication();
            if (latestPublication != null)
            {
                builder.Append(", last publication: ").Append(latestPublication.PublicationData.PublicationTime);
            }

            if (_publicationsHeader.RepositoryUri != null)
            {
                builder.Append(", published at: ").Append(_publicationsHeader.RepositoryUri);
            }

            return builder.ToString();
        }
    }
}