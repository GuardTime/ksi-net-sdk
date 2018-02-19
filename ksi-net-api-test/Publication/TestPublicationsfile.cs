/*
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
using Guardtime.KSI.Publication;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Test.Publication
{
    public class TestPublicationsFile : IPublicationsFile
    {
        public uint Type => 0;
        public bool NonCritical => false;
        public bool Forward => false;

        public byte[] EncodeValueBytes;
        public byte[] EncodedBytes;

        public List<PublicationRecordInPublicationFile> PublicationRecords = new List<PublicationRecordInPublicationFile>();

        public List<CertificateRecord> CertificateRecords = new List<CertificateRecord>();

        public Dictionary<ulong, PublicationRecordInPublicationFile> NearestPublications = new Dictionary<ulong, PublicationRecordInPublicationFile>();
        public PublicationRecordInPublicationFile LatestPublication;

        public byte[] EncodeValue()
        {
            return EncodeValueBytes;
        }

        public byte[] Encode()
        {
            return EncodedBytes;
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

        public PublicationRecordInPublicationFile GetNearestPublicationRecord(DateTime time)
        {
            ulong t = Util.ConvertDateTimeToUnixTime(time);
            return NearestPublications.ContainsKey(t) ? NearestPublications[t] : null;
        }

        public PublicationRecordInPublicationFile GetLatestPublication()
        {
            return LatestPublication;
        }
    }
}