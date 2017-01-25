/*
 * Copyright 2013-2016 Guardtime, Inc.
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

using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Test.Signature
{
    public class TestKsiSignature : IKsiSignature
    {
        public Rfc3161Record Rfc3161Record { get; set; }

        public bool IsRfc3161Signature => Rfc3161Record != null;

        public CalendarHashChain CalendarHashChain { get; set; }
        public CalendarAuthenticationRecord CalendarAuthenticationRecord { get; set; }
        public PublicationRecordInSignature PublicationRecord { get; set; }
        public ulong AggregationTime { get; set; }

        public ReadOnlyCollection<AggregationHashChain> AggregationHashChains;
        public DataHash AggregationHashChainRootHash;
        public IKsiSignature ExtendedKsiSignature;

        public ITlvTag this[int i] => null;

        public int Count => 0;

        /// <summary>
        ///     Get Enumerator for TLV composite element.
        /// </summary>
        /// <returns>TLV composite elemnet enumerator.</returns>
        public IEnumerator<ITlvTag> GetEnumerator()
        {
            return null;
        }

        /// <summary>
        ///     Get Enumerator for TLV composite element.
        /// </summary>
        /// <returns>TLV composite elemnet enumerator.</returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
        {
            return AggregationHashChains;
        }

        public DataHash GetAggregationHashChainRootHash()
        {
            return AggregationHashChainRootHash;
        }

        public IKsiSignature Extend(CalendarHashChain calendarHashChain, IKsiSignatureFactory signatureFactory)
        {
            return ExtendedKsiSignature;
        }

        public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInPublicationFile publicationRecord, IKsiSignatureFactory signatureFactory)
        {
            return ExtendedKsiSignature;
        }

        public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInSignature publicationRecord, IKsiSignatureFactory signatureFactory)
        {
            return ExtendedKsiSignature;
        }

        public void SetFirstLinkLevelCorrection(uint levelCorrection)
        {
            GetAggregationHashChains()[0].GetChainLinks()[0].SetLevelCorrection(0);
        }

        public void WriteTo(Stream outputStream)
        {
            using (TlvWriter writer = new TlvWriter(outputStream))
            {
                writer.WriteTag(this);
            }
        }

        public uint Type { get; set; }
        public bool NonCritical { get; set; }
        public bool Forward { get; set; }

        public byte[] EncodedValue;

        public byte[] EncodeValue()
        {
            return EncodedValue;
        }

        public string Identity => "Test";

        public bool IsExtended => PublicationRecord != null;

        public IEnumerable<IIdentity> GetIdentity()
        {
            return new[] { new LegacyIdentity("Test") };
        }

    }
}