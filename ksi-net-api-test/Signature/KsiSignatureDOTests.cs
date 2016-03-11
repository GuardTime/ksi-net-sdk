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

using System;
using System.IO;
using System.Reflection;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class KsiSignatureDoTests
    {
        [Test]
        public void TestKsiSignatureDoOk()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok);
            Assert.NotNull(signature.CalendarHashChain, "Calendar hash chain cannot be null");
        }

        [Test]
        public void TestKsiSignatureDoWithMixedAggregationChais()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_With_Mixed_Aggregation_Chains);
            Assert.NotNull(signature, "Signature cannot be null");
        }

        [Test]
        public void TestKsiSignatureIsExtended()
        {
            IKsiSignature signature1 = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_With_Mixed_Aggregation_Chains);
            Assert.False(signature1.IsExtended, "IsExtended should be false.");

            IKsiSignature signature2 = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record);
            Assert.True(signature2.IsExtended, "IsExtended should be true.");
        }

        [Test]
        public void TestKsiSignatureIdentity()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_With_Mixed_Aggregation_Chains);
            Assert.True(signature.Identity == "anon.taavi-test.testA.GT", "Identity has invalid value.");
        }

        [Test]
        public void TestKsiSignatureDoOkMissingCalendarHashChain()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_Missing_Calendar_Hash_Chain);
            Assert.Null(signature.CalendarHashChain, "Calendar hash chain must be null");
        }

        [Test]
        public void TestKsiSignatureDoOkMissingPublicationRecord()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record);
            Assert.Null(signature.PublicationRecord, "Publication record must be null");
            Assert.Null(signature.CalendarAuthenticationRecord, "Calendar authentication record must be null");
        }

        [Test]
        public void TestLegacyKsiSignatureDoOk()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Legacy_Ok);
            Assert.IsTrue(signature.IsRfc3161Signature, "RFC3161 tag must exist");
        }

        [Test]
        public void TestKsiSignatureDoInvalidType()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Type);
            }, "Invalid signature type: 2201");
        }

        [Test]
        public void TestKsiSignatureDoInvalidContainsPublicationRecordAndCalendarAuthenticationRecord()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Contain_Publication_Record_And_Calendar_Authentication_Record);
            }, "Only one from publication record or calendar authentication record is allowed in signature data object");
        }

        [Test]
        public void TestKsiSignatureDoInvalidExtraTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Extra_Tag);
            }, "Invalid tag");
        }

        [Test]
        public void TestKsiSignatureDoInvalidMissingAggregationHashChain()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Missing_Aggregation_Hash_Chain);
            }, "Aggregation hash chains must exist in signature data object");
        }

        [Test]
        public void TestKsiSignatureDoInvalidMissingCalendarHashChain()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Missing_Calendar_Hash_Chain);
            }, "No publication record or calendar authentication record is allowed in signature data object if there is no calendar hash chain");
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultipleCalendarAuthenticationRecords()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Calendar_Authentication_Records);
            }, "Only one from publication record or calendar authentication record is allowed in signature data object");
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultipleCalendarHashChain()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Calendar_Hash_Chains);
            }, "Only one calendar hash chain is allowed in signature data object");
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultiplePublicationRecords()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Publication_Records);
            }, "Only one from publication record or calendar authentication record is allowed in signature data object");
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultipleRfc3161Records()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Rfc_3161_Records);
            }, "Only one RFC 3161 record is allowed in signature data object");
        }

        // TODO: Multiple aggregation authentication record test is missing

        private static IKsiSignature GetKsiSignatureDoFromFile(string file)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open))
            {
                return new KsiSignatureFactory().Create(stream);
            }
        }

        [Test]
        public void ToStringWithPublicationRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+MetaData");

            KsiSignature tag = TestUtil.GetCompositeTag<KsiSignature>(Constants.KsiSignature.TagType,
                new ITlvTag[]
                {
                    TestUtil.GetCompositeTag<AggregationHashChain>(Constants.AggregationHashChain.TagType,
                        new ITlvTag[]
                        {
                            new IntegerTag(Constants.AggregationHashChain.AggregationTimeTagType, false, false, 1),
                            new IntegerTag(Constants.AggregationHashChain.ChainIndexTagType, false, false, 0),
                            new RawTag(Constants.AggregationHashChain.InputDataTagType, false, false, new byte[] { 0x1 }),
                            new ImprintTag(Constants.AggregationHashChain.InputHashTagType, false, false,
                                new DataHash(HashAlgorithm.Sha2256,
                                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                            new IntegerTag(Constants.AggregationHashChain.AggregationAlgorithmIdTagType, false, false, 1),
                            TestUtil.GetCompositeTag(aggregationLinkType, (uint)LinkDirection.Left,
                                new ITlvTag[]
                                {
                                    new IntegerTag(Constants.AggregationHashChain.Link.LevelCorrectionTagType, false, false, 0),
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.MetaData.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.MetaData.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.MetaData.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.MetaData.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.MetaData.RequestTimeTagType, false, false, 2)
                                        })
                                },
                                LinkDirection.Left)
                        }),
                    TestUtil.GetCompositeTag<CalendarHashChain>(Constants.CalendarHashChain.TagType,
                        new ITlvTag[]
                        {
                            new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1),
                            new IntegerTag(Constants.CalendarHashChain.AggregationTimeTagType, false, false, 0),
                            new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                                new DataHash(HashAlgorithm.Sha2256,
                                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                            // add links
                            (ITlvTag)Activator.CreateInstance(calendarLinkType, new ImprintTag((uint)LinkDirection.Left, false, false,
                                new DataHash(HashAlgorithm.Sha2256,
                                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })))
                        }),
                    TestUtil.GetCompositeTag<PublicationRecordInSignature>(Constants.PublicationRecord.TagTypeInSignature,
                        new ITlvTag[]
                        {
                            TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                                new ITlvTag[]
                                {
                                    new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                    new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                        new DataHash(HashAlgorithm.Sha2256,
                                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                }),
                            new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 1"),
                            new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 2"),
                            new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 1"),
                            new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 2"),
                        }),
                    TestUtil.GetCompositeTag<AggregationAuthenticationRecord>(Constants.AggregationAuthenticationRecord.TagType,
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
                        }),
                    TestUtil.GetCompositeTag<Rfc3161Record>(Constants.Rfc3161Record.TagType,
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
                        })
                });

            KsiSignature tag2 = new KsiSignature(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");

            Assert.AreEqual(@"TLV[0x800]:
  TLV[0x801]:
    TLV[0x2]:i1
    TLV[0x3]:i0
    TLV[0x4]:0x01
    TLV[0x5]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0x6]:i1
    TLV[0x7]:
      TLV[0x1]:i0
      TLV[0x4]:
        TLV[0x1]:""Test ClientId""
        TLV[0x2]:""Test Machine Id""
        TLV[0x3]:i1
        TLV[0x4]:i2
  TLV[0x802]:
    TLV[0x1]:i1
    TLV[0x2]:i0
    TLV[0x5]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0x7]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
  TLV[0x803]:
    TLV[0x10]:
      TLV[0x2]:i1
      TLV[0x4]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0x9]:""Test publication reference 1""
    TLV[0x9]:""Test publication reference 2""
    TLV[0xA]:""Test publication repository uri 1""
    TLV[0xA]:""Test publication repository uri 2""
  TLV[0x804]:
    TLV[0x2]:i1
    TLV[0x3]:i0
    TLV[0x5]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0xB]:
      TLV[0x1]:""Test SignatureType""
      TLV[0x2]:0x02
      TLV[0x3]:0x03
      TLV[0x4]:""Test CertificateRepositoryUri""
  TLV[0x806]:
    TLV[0x2]:i1
    TLV[0x3]:i1
    TLV[0x5]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0x10]:0x02
    TLV[0x11]:0x03
    TLV[0x12]:i1
    TLV[0x13]:0x02
    TLV[0x14]:0x03
    TLV[0x15]:i1", tag.ToString(), "Invalid signature string");
        }

        [Test]
        public void ToStringWithCalendarAuthenticationRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+MetaData");

            KsiSignature tag = TestUtil.GetCompositeTag<KsiSignature>(Constants.KsiSignature.TagType,
                new ITlvTag[]
                {
                    TestUtil.GetCompositeTag<AggregationHashChain>(Constants.AggregationHashChain.TagType,
                        new ITlvTag[]
                        {
                            new IntegerTag(Constants.AggregationHashChain.AggregationTimeTagType, false, false, 1),
                            new IntegerTag(Constants.AggregationHashChain.ChainIndexTagType, false, false, 0),
                            new RawTag(Constants.AggregationHashChain.InputDataTagType, false, false, new byte[] { 0x1 }),
                            new ImprintTag(Constants.AggregationHashChain.InputHashTagType, false, false,
                                new DataHash(HashAlgorithm.Sha2256,
                                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                            new IntegerTag(Constants.AggregationHashChain.AggregationAlgorithmIdTagType, false, false, 1),
                            TestUtil.GetCompositeTag(aggregationLinkType, (uint)LinkDirection.Left,
                                new ITlvTag[]
                                {
                                    new IntegerTag(Constants.AggregationHashChain.Link.LevelCorrectionTagType, false, false, 0),
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.MetaData.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.MetaData.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.MetaData.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.MetaData.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.MetaData.RequestTimeTagType, false, false, 2)
                                        })
                                },
                                LinkDirection.Left)
                        }),
                    TestUtil.GetCompositeTag<CalendarHashChain>(Constants.CalendarHashChain.TagType,
                        new ITlvTag[]
                        {
                            new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1),
                            new IntegerTag(Constants.CalendarHashChain.AggregationTimeTagType, false, false, 0),
                            new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                                new DataHash(HashAlgorithm.Sha2256,
                                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                            // add links
                            (ITlvTag)Activator.CreateInstance(calendarLinkType, new ImprintTag((uint)LinkDirection.Left, false, false,
                                new DataHash(HashAlgorithm.Sha2256,
                                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })))
                        }),
                    TestUtil.GetCompositeTag<AggregationAuthenticationRecord>(Constants.AggregationAuthenticationRecord.TagType,
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
                        }),
                    TestUtil.GetCompositeTag<CalendarAuthenticationRecord>(Constants.CalendarAuthenticationRecord.TagType,
                        new ITlvTag[]
                        {
                            TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                                new ITlvTag[]
                                {
                                    new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                    new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                        new DataHash(HashAlgorithm.Sha2256,
                                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                }),
                            TestUtil.GetCompositeTag<SignatureData>(Constants.SignatureData.TagType,
                                new ITlvTag[]
                                {
                                    new StringTag(Constants.SignatureData.SignatureTypeTagType, false, false, "Test SignatureType"),
                                    new RawTag(Constants.SignatureData.SignatureValueTagType, false, false, new byte[] { 0x2 }),
                                    new RawTag(Constants.SignatureData.CertificateIdTagType, false, false, new byte[] { 0x3 }),
                                    new StringTag(Constants.SignatureData.CertificateRepositoryUriTagType, false, false, "Test CertificateRepositoryUri")
                                })
                        }),
                    TestUtil.GetCompositeTag<Rfc3161Record>(Constants.Rfc3161Record.TagType,
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
                        })
                });

            KsiSignature tag2 = new KsiSignature(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");

            Assert.AreEqual(@"TLV[0x800]:
  TLV[0x801]:
    TLV[0x2]:i1
    TLV[0x3]:i0
    TLV[0x4]:0x01
    TLV[0x5]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0x6]:i1
    TLV[0x7]:
      TLV[0x1]:i0
      TLV[0x4]:
        TLV[0x1]:""Test ClientId""
        TLV[0x2]:""Test Machine Id""
        TLV[0x3]:i1
        TLV[0x4]:i2
  TLV[0x802]:
    TLV[0x1]:i1
    TLV[0x2]:i0
    TLV[0x5]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0x7]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
  TLV[0x804]:
    TLV[0x2]:i1
    TLV[0x3]:i0
    TLV[0x5]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0xB]:
      TLV[0x1]:""Test SignatureType""
      TLV[0x2]:0x02
      TLV[0x3]:0x03
      TLV[0x4]:""Test CertificateRepositoryUri""
  TLV[0x805]:
    TLV[0x10]:
      TLV[0x2]:i1
      TLV[0x4]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0xB]:
      TLV[0x1]:""Test SignatureType""
      TLV[0x2]:0x02
      TLV[0x3]:0x03
      TLV[0x4]:""Test CertificateRepositoryUri""
  TLV[0x806]:
    TLV[0x2]:i1
    TLV[0x3]:i1
    TLV[0x5]:0x010102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
    TLV[0x10]:0x02
    TLV[0x11]:0x03
    TLV[0x12]:i1
    TLV[0x13]:0x02
    TLV[0x14]:0x03
    TLV[0x15]:i1", tag.ToString(), "Invalid signature string");
        }
    }
}