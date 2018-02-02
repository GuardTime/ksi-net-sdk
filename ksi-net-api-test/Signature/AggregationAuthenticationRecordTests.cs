/*
 * Copyright 2013-2017 Guardtime, Inc.
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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class AggregationAuthenticationRecordTests
    {
        [Test]
        public void TestAggregationAuthenticationRecordOk()
        {
            AggregationAuthenticationRecord aggregationAuthenticationRecord = GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Ok);
            Assert.AreEqual(5, aggregationAuthenticationRecord.Count, "Invalid amount of child TLV objects");
            Assert.AreEqual(1436440218, aggregationAuthenticationRecord.AggregationTime, "Unexpected aggregation time.");
            Assert.AreEqual(new DataHash(Base16.Decode("0127ECD0A598E76F8A2FD264D427DF0A119903E8EAE384E478902541756F089DD1")), aggregationAuthenticationRecord.InputHash,
                "Unexpected input hash.");
            Assert.IsNotNull(aggregationAuthenticationRecord.SignatureData, "Unexpected signature data: null");
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidExtraTag()
        {
            Assert.That(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Invalid_Extra_Tag);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Unknown tag type"));
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMissingAggregationTime()
        {
            Assert.That(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Invalid_Missing_Aggregation_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one aggregation time must exist in aggregation authentication record"));
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMissingChainIndex()
        {
            Assert.That(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Invalid_Missing_Chain_Index);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Chain indexes must exist in aggregation authentication record"));
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMissingInputHash()
        {
            Assert.That(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Invalid_Missing_Input_Hash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one input hash must exist in aggregation authentication record"));
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMissingSignatureData()
        {
            Assert.That(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Invalid_Missing_Signature_Data);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one signature data must exist in aggregation authentication record"));
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMultipleAggregationTime()
        {
            Assert.That(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Invalid_Multiple_Aggregation_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one aggregation time must exist in aggregation authentication record"));
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMultipleInputHash()
        {
            Assert.That(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Invalid_Multiple_Input_Hash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one input hash must exist in aggregation authentication record"));
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMultipleSignatureData()
        {
            Assert.That(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Invalid_Multiple_Signature_Data);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one signature data must exist in aggregation authentication record"));
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidType()
        {
            Assert.That(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Resources.AggregationAuthenticationRecord_Invalid_Type);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Invalid tag type! Class: AggregationAuthenticationRecord; Type: 0x805;"));
        }

        [Test]
        public void ToStringTest()
        {
            AggregationAuthenticationRecord tag = TestUtil.GetCompositeTag<AggregationAuthenticationRecord>(Constants.AggregationAuthenticationRecord.TagType,
                new ITlvTag[]
                {
                    new IntegerTag(Constants.AggregationAuthenticationRecord.AggregationTimeTagType, false, false, 1),
                    new IntegerTag(Constants.AggregationAuthenticationRecord.ChainIndexTagType, false, false, 0),
                    new ImprintTag(Constants.AggregationAuthenticationRecord.InputHashTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                    TestUtil.GetCompositeTag<SignatureData>(Constants.SignatureData.TagType,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.SignatureData.SignatureTypeTagType, false, false, "Test SignatureType"),
                            new RawTag(Constants.SignatureData.SignatureValueTagType, false, false, new byte[] { 0x2 }),
                            new RawTag(Constants.SignatureData.CertificateIdTagType, false, false, new byte[] { 0x3 }),
                            new StringTag(Constants.SignatureData.CertificateRepositoryUriTagType, false, false, "Test CertificateRepositoryUri")
                        })
                });

            AggregationAuthenticationRecord tag2 = new AggregationAuthenticationRecord(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        private static AggregationAuthenticationRecord GetAggregationAuthenticationRecordFromFile(string file)
        {
            return new AggregationAuthenticationRecord(TestUtil.GetRawTag(file));
        }
    }
}