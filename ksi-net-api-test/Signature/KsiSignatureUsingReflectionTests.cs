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

using System;
using System.IO;
using System.Reflection;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Test.Signature.Verification;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class KsiSignatureUsingReflectionTests
    {
        /// <summary>
        /// Test ToString method. Signature contains a publication record
        /// </summary>
        [Test]
        public void ToStringWithPublicationRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
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

            KsiSignature tag2 = new KsiSignature(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

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

        /// <summary>
        /// Test ToString method. Signature contains a calendar auth record
        /// </summary>
        [Test]
        public void ToStringWithCalendarAuthenticationRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
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

            KsiSignature tag2 = new KsiSignature(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

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

        /// <summary>
        /// Test signature containing only aggregation chain tags (single)
        /// Expected result: success
        /// </summary>
        [Test]
        public void SignatureContainingOnlyAggregationChainTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
                        })
                });

            Assert.DoesNotThrow(delegate
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.WriteTag(tag);
                    writer.BaseStream.Seek(0, SeekOrigin.Begin);
                    IKsiSignature tag2 = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(writer.BaseStream);
                    Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");
                }
            });
        }

        /// <summary>
        /// Test signature containing only aggregation chain tags (multiple)
        /// Expected result: success
        /// </summary>
        [Test]
        public void SignatureContainingOnlyAggregationChainsTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
                        }),
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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
                        })
                });

            Assert.DoesNotThrow(delegate
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.WriteTag(tag);
                    writer.BaseStream.Seek(0, SeekOrigin.Begin);
                    IKsiSignature tag2 = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(writer.BaseStream);
                    Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");
                }
            });
        }

        /// <summary>
        /// Testing signature containing single calendar hash chain
        /// Expected result: success
        /// </summary>
        [Test]
        public void SignatureContainingSingleCalendarHashChainTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
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
                });

            Assert.DoesNotThrow(delegate
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.WriteTag(tag);
                    writer.BaseStream.Seek(0, SeekOrigin.Begin);
                    IKsiSignature tag2 = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(writer.BaseStream);
                    Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");
                }
            });
        }

        /// <summary>
        /// Testing signature containing multiple calendar hash chains
        /// Expected result: TlvException
        /// </summary>
        [Test]
        public void SignatureContainingMultipleCalendarHashChainsTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

            Assert.That(delegate
            {
                TestUtil.GetCompositeTag<KsiSignature>(Constants.KsiSignature.TagType,
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
                                        TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                            new ITlvTag[]
                                            {
                                                new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                                new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                                new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                                new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                            })
                                    })
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
                    });
            }, Throws.InnerException.TypeOf<TlvException>());
        }

        /// <summary>
        /// Testing signature containing single rfc3161 record
        /// Expected result: success
        /// </summary>
        [Test]
        public void SignatureContainingSingleRfc3161RecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
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
                        }),
                });

            Assert.DoesNotThrow(delegate
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.WriteTag(tag);
                    writer.BaseStream.Seek(0, SeekOrigin.Begin);
                    IKsiSignature tag2 = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(writer.BaseStream);
                    Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");
                }
            });
        }

        /// <summary>
        /// Testing signature containing multiple rfc3161 records
        /// Expected result: TlvException
        /// </summary>
        [Test]
        public void SignatureContainingMultipleRfc3161RecordsTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

            Assert.That(delegate
            {
                TestUtil.GetCompositeTag<KsiSignature>(Constants.KsiSignature.TagType,
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
                                        TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                            new ITlvTag[]
                                            {
                                                new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                                new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                                new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                                new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                            })
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
            }, Throws.InnerException.TypeOf<TlvException>());
        }

        /// <summary>
        /// Testing signature containing a calendar hash chain, a publication record and a calendar auth record
        /// Expected result: TlvException
        /// </summary>
        [Test]
        public void SignatureWithCalendarHashChainAndPublicationRecordAndCalendarAuthRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

            Assert.That(delegate
            {
                TestUtil.GetCompositeTag<KsiSignature>(Constants.KsiSignature.TagType,
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
                                        TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                            new ITlvTag[]
                                            {
                                                new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                                new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                                new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                                new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                            })
                                    })
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
                        TestUtil.GetCompositeTag<CalendarAuthenticationRecord>(Constants.CalendarAuthenticationRecord.TagType,
                            new ITlvTag[]
                            {
                                TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                                    new ITlvTag[]
                                    {
                                        new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                        new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[]
                                                {
                                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                                                })),
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
                        TestUtil.GetCompositeTag<PublicationRecordInSignature>(Constants.PublicationRecord.TagTypeInSignature,
                            new ITlvTag[]
                            {
                                TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                                    new ITlvTag[]
                                    {
                                        new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                        new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[]
                                                {
                                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                                                })),
                                    }),
                                new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 1"),
                                new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 2"),
                                new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 1"),
                                new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 2"),
                            }),
                    });
            }, Throws.InnerException.TypeOf<TlvException>());
        }

        /// <summary>
        /// Testing signature containing a calendar hash chain and publication record
        /// Expected result: success
        /// </summary>
        [Test]
        public void SignatureWithCalendarHashChainAndPublicationRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
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
                });

            Assert.DoesNotThrow(delegate
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.WriteTag(tag);
                    writer.BaseStream.Seek(0, SeekOrigin.Begin);
                    IKsiSignature tag2 = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(writer.BaseStream);
                    Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");
                }
            });
        }

        /// <summary>
        /// Testing signature containing a calendar hash chain and a calendar auth record
        /// Expected result: success
        /// </summary>
        [Test]
        public void SignatureWithCalendarHashChainAndCalendarAuthRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
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
                });

            Assert.DoesNotThrow(delegate
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.WriteTag(tag);
                    writer.BaseStream.Seek(0, SeekOrigin.Begin);
                    IKsiSignature tag2 = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(writer.BaseStream);
                    Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");
                }
            });
        }

        /// <summary>
        /// Testing signature containing a calendar hash chain (no publication record and no calendar auth record)
        /// Expected result: success
        /// </summary>
        [Test]
        public void SignatureWithCalendarHashChainNoPublicationRecordNoCalendarAuthRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
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
                });

            Assert.DoesNotThrow(delegate
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.WriteTag(tag);
                    writer.BaseStream.Seek(0, SeekOrigin.Begin);
                    IKsiSignature tag2 = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(writer.BaseStream);
                    Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");
                }
            });
        }

        /// <summary>
        /// Testing signature containing one of each possible compoonents
        /// Expected result: TlvException
        /// </summary>
        [Test]
        public void SignatureContainingOneOfAllTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

            Assert.That(delegate
            {
                TestUtil.GetCompositeTag<KsiSignature>(Constants.KsiSignature.TagType,
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
                                        TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                            new ITlvTag[]
                                            {
                                                new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                                new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                                new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                                new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                            })
                                    })
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

                        TestUtil.GetCompositeTag<CalendarAuthenticationRecord>(Constants.CalendarAuthenticationRecord.TagType,
                            new ITlvTag[]
                            {
                                TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                                    new ITlvTag[]
                                    {
                                        new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                        new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[]
                                                {
                                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                                                })),
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
                        TestUtil.GetCompositeTag<PublicationRecordInSignature>(Constants.PublicationRecord.TagTypeInSignature,
                            new ITlvTag[]
                            {
                                TestUtil.GetCompositeTag<PublicationData>(Constants.PublicationData.TagType,
                                    new ITlvTag[]
                                    {
                                        new IntegerTag(Constants.PublicationData.PublicationTimeTagType, false, false, 1),
                                        new ImprintTag(Constants.PublicationData.PublicationHashTagType, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[]
                                                {
                                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                                                })),
                                    }),
                                new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 1"),
                                new StringTag(Constants.PublicationRecord.PublicationReferencesTagType, false, false, "Test publication reference 2"),
                                new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 1"),
                                new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test publication repository uri 2"),
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
            }, Throws.InnerException.TypeOf<TlvException>());
        }

        /// <summary>
        /// Testing signature containing one of each possible compoonents except publication record
        /// Expected result: success
        /// </summary>
        [Test]
        public void SignatureContainingOneOfAllExceptPublicationRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
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

            Assert.DoesNotThrow(delegate
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.WriteTag(tag);
                    writer.BaseStream.Seek(0, SeekOrigin.Begin);
                    IKsiSignature tag2 = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(writer.BaseStream);
                    Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");
                }
            });
        }

        /// <summary>
        /// Testing signature containing one of each possible compoonents except calendar auth record
        /// Expected result: success
        /// </summary>
        [Test]
        public void SignatureContainingOneOfAllExceptCalendarAuthenticationRecordTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type calendarLinkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");
            Type aggregationLinkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

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
                                    TestUtil.GetCompositeTag(metadataType, Constants.AggregationHashChain.Metadata.TagType,
                                        new ITlvTag[]
                                        {
                                            new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, "Test ClientId"),
                                            new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, "Test Machine Id"),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, 1),
                                            new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, 2)
                                        })
                                })
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

            Assert.DoesNotThrow(delegate
            {
                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    writer.WriteTag(tag);
                    writer.BaseStream.Seek(0, SeekOrigin.Begin);
                    IKsiSignature tag2 = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(writer.BaseStream);
                    Assert.AreEqual(tag.ToString(), tag2.ToString(), "Signatures' strings should match.");
                }
            });
        }
    }
}