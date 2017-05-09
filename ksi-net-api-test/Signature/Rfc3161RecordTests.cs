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

using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class Rfc3161RecordTests
    {
        [Test]
        public void TestRfc3161RecordOk()
        {
            Rfc3161Record rfc3161Record = GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Ok);
            Assert.AreEqual(10, rfc3161Record.Count, "Invalid amount of child TLV objects");

            Assert.AreEqual(rfc3161Record.GetOutputHash(),
                new DataHash(HashAlgorithm.Sha2256, Base16.Decode("C96682043DB0474031CEF1AE12941523E59BDC64E62CDAAE817CE46370918648")), "Output hash should be correctly calculated");
        }

        [Test]
        public void TestRfc3161RecordInvalidType()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Type);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Invalid tag type! Class: Rfc3161Record; Type: 0x807;"));
        }

        [Test]
        public void TestRfc3161RecordInvalidExtraTag()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Extra_Tag);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Unknown tag"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingAggregationTime()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Aggregation_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one aggregation time must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingChainIndex()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Chain_Index);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Chain indexes must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingInputHash()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Input_Hash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one input hash must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingSignedAttributesAlgorithm()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Signed_Attributes_Algorithm);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one signed attributes algorithm must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingSignedAttributesPrefix()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Signed_Attributes_Prefix);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one signed attributes prefix must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingSignedAttributesSuffix()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Signed_Attributes_Suffix);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one signed attributes suffix must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingTstInfoAlgorithm()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_TstInfo_Algorithm);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one tstInfo algorithm must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingTstInfoPrefix()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_TstInfo_Prefix);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one tstInfo prefix must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingTstInfoSuffix()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_TstInfo_Suffix);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one tstInfo suffix must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleAggregationTime()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Aggregation_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one aggregation time must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleInputHash()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Input_Hash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one input hash must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleSignedAttributesAlgorithm()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Signed_Attributes_Algorithm);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one signed attributes algorithm must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleSignedAttributesPrefix()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Signed_Attributes_Prefix);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one signed attributes prefix must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleSignedAttributesSuffix()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Signed_Attributes_Suffix);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one signed attributes suffix must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleTstInfoAlgorithm()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_TstInfo_Algorithm);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one tstInfo algorithm must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleTstInfoPrefix()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_TstInfo_Prefix);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one tstInfo prefix must exist in RFC#3161 record"));
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleTstInfoSuffix()
        {
            Assert.That(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_TstInfo_Suffix);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one tstInfo suffix must exist in RFC#3161 record"));
        }

        [Test]
        public void ToStringTest()
        {
            Rfc3161Record tag = TestUtil.GetCompositeTag<Rfc3161Record>(Constants.Rfc3161Record.TagType,
                new ITlvTag[]
                {
                    new IntegerTag(Constants.Rfc3161Record.AggregationTimeTagType, false, false, 1),
                    new IntegerTag(Constants.Rfc3161Record.ChainIndexTagType, false, false, 1),
                    new ImprintTag(Constants.Rfc3161Record.InputHashTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                    new RawTag(Constants.Rfc3161Record.TstInfoPrefixTagType, false, false, new byte[] { 0x2 }),
                    new RawTag(Constants.Rfc3161Record.TstInfoSuffixTagType, false, false, new byte[] { 0x3 }),
                    new IntegerTag(Constants.Rfc3161Record.TstInfoAlgorithmTagType, false, false, 1),
                    new RawTag(Constants.Rfc3161Record.SignedAttributesPrefixTagType, false, false, new byte[] { 0x2 }),
                    new RawTag(Constants.Rfc3161Record.SignedAttributesSuffixTagType, false, false, new byte[] { 0x3 }),
                    new IntegerTag(Constants.Rfc3161Record.SignedAttributesAlgorithmTagType, false, false, 1),
                });

            Rfc3161Record tag2 = new Rfc3161Record(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        private static Rfc3161Record GetRfc3161RecordFromFile(string file)
        {
            using (TlvReader reader = new TlvReader(new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open)))
            {
                Rfc3161Record rfc3161Record = new Rfc3161Record(reader.ReadTag());

                return rfc3161Record;
            }
        }
    }
}