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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using System.Text;
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
    public class AggregationHashChainTests
    {
        [Test]
        public void TestCreateAggregationHashChainOk()
        {
            AggregationHashChain aggregationHashChain = GetAggregationHashChainFromFile(Resources.AggregationHashChain_Ok);
            Assert.AreEqual(9, aggregationHashChain.Count, "Invalid amount of child TLV objects");
            Assert.IsNotNull(aggregationHashChain.GetInputData(), "Unexpected input data.");
        }

        [Test]
        public void TestCreateAggregationHashChainFromChildTags()
        {
            AggregationHashChain aggregationHashChain = new AggregationHashChain(false, false, GetAggregationHashChainFromFile(Resources.AggregationHashChain_Ok).ToArray());
            Assert.AreEqual(9, aggregationHashChain.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestCreateAggregationHashChainWithLinksOk()
        {
            ReadOnlyCollection<AggregationHashChain.Link> links = GetAggregationHashChainFromFile(Resources.AggregationHashChain_Ok).GetChainLinks();
            AggregationHashChain newAggregationHashChain = new AggregationHashChain(1, new ulong[] { 1 },
                new DataHash(Base16.Decode("01404572B3A03FCBB57D265903A153B24237F277723D1B24A199F9F009A4EB23BE")),
                1, links.ToArray());
            Assert.AreEqual(links.Count, newAggregationHashChain.GetChainLinks().Count, "Unexpected links count");
            Assert.AreEqual(LinkDirection.Left, links[0].Direction, "Unexpected link direction");
            Assert.AreEqual(new DataHash(Base16.Decode("01E8EE4A17C22DFA36839998F24DEC73E78DA7B0A92FF3530570AF98117F406DDF")), links[0].SiblingHash, "Unexpected sibling hash");
            Assert.IsNull(links[0].Metadata, "Unexpected metadata");
        }

        [Test]
        public void TestCreateAggregationHashChainWithoutChainIndex()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new AggregationHashChain(1, null, new DataHash(Base16.Decode("01404572B3A03FCBB57D265903A153B24237F277723D1B24A199F9F009A4EB23BE")),
                    1, new AggregationHashChain.Link[] { });
            });

            Assert.AreEqual("chainIndex", ex.ParamName);
        }

        [Test]
        public void TestCreateAggregationHashChainWithChainLinksNull()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new AggregationHashChain(1, new ulong[] { 1 }, new DataHash(Base16.Decode("01404572B3A03FCBB57D265903A153B24237F277723D1B24A199F9F009A4EB23BE")),
                    1, null);
            });

            Assert.AreEqual("chainLinks", ex.ParamName);
        }

        [Test]
        public void TestCreateAggregationHashChainWithEmptyChainLinks()
        {
            Assert.That(delegate
            {
                new AggregationHashChain(1, new ulong[] { 1 }, new DataHash(Base16.Decode("01404572B3A03FCBB57D265903A153B24237F277723D1B24A199F9F009A4EB23BE")),
                    1, new AggregationHashChain.Link[] { });
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Links are missing in aggregation hash chain"));
        }

        [Test]
        public void TestGetOutputHashWithoutResult()
        {
            AggregationHashChain aggregationHashChain = GetAggregationHashChainFromFile(Resources.AggregationHashChain_Ok);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                aggregationHashChain.GetOutputHash(null);
            });

            Assert.AreEqual("result", ex.ParamName);
        }

        [Test]
        public void TestGetOutputHash()
        {
            AggregationHashChain aggregationHashChain = GetAggregationHashChainFromFile(Resources.AggregationHashChain_Ok);
            AggregationHashChainResult result = new AggregationHashChainResult(1, aggregationHashChain.InputHash);
            result = aggregationHashChain.GetOutputHash(result);
            Assert.AreEqual(new DataHash(Base16.Decode("0116FF519501549E59F94952234BEAE90D1AB708901AF7B3F92B88B6A441969541")), result.Hash, "Unexpected output hash.");
            Assert.AreEqual(29, result.Level, "Unexpected level.");
        }

        [Test]
        public void TestGetLocationPointer()
        {
            Assert.AreEqual(63,
                AggregationHashChain.CalcLocationPointer(new List<AggregationHashChain.Link>
                {
                    new AggregationHashChain.Link(LinkDirection.Left, new AggregationHashChain.Metadata("test client", "test machine id")),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01404572B3A03FCBB57D265903A153B24237F277723D1B24A199F9F009A4EB23BE"))),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("0160D25FD6F2A962B41F20CFC2DD9CC62C9C802EADB08E8F15E60D0316E778ACDC"))),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01F2960B44B6846AE20FD4169D599D9F1C405A6CB1CBAA5B3179A06B3D1DB92166"))),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01F2960B44B6846AE20FD4169D599D9F1C405A6CB1CBAA5B3179A06B3D1DB92166"))),
                }.ToArray()), "Invalid location pointer.");

            Assert.AreEqual(51,
                AggregationHashChain.CalcLocationPointer(new List<AggregationHashChain.Link>
                {
                    new AggregationHashChain.Link(LinkDirection.Left, "test client", "test machine id"),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01404572B3A03FCBB57D265903A153B24237F277723D1B24A199F9F009A4EB23BE"))),
                    new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("0160D25FD6F2A962B41F20CFC2DD9CC62C9C802EADB08E8F15E60D0316E778ACDC"))),
                    new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("01F2960B44B6846AE20FD4169D599D9F1C405A6CB1CBAA5B3179A06B3D1DB92166"))),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01F2960B44B6846AE20FD4169D599D9F1C405A6CB1CBAA5B3179A06B3D1DB92166"))),
                }.ToArray()), "Invalid location pointer.");

            Assert.AreEqual(23, AggregationHashChain.CalcLocationPointer(new List<AggregationHashChain.Link>
            {
                new AggregationHashChain.Link(LinkDirection.Left, new AggregationHashChain.Metadata("test client", "test machine id")),
                new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01404572B3A03FCBB57D265903A153B24237F277723D1B24A199F9F009A4EB23BE"))),
                new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("0160D25FD6F2A962B41F20CFC2DD9CC62C9C802EADB08E8F15E60D0316E778ACDC"))),
                new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("01F2960B44B6846AE20FD4169D599D9F1C405A6CB1CBAA5B3179A06B3D1DB92166"))),
            }.ToArray()), "Invalid location pointer.");

            Assert.AreEqual(21, AggregationHashChain.CalcLocationPointer(new List<AggregationHashChain.Link>
            {
                new AggregationHashChain.Link(LinkDirection.Left, new AggregationHashChain.Metadata("test client", "test machine id")),
                new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("01404572B3A03FCBB57D265903A153B24237F277723D1B24A199F9F009A4EB23BE"))),
                new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("0160D25FD6F2A962B41F20CFC2DD9CC62C9C802EADB08E8F15E60D0316E778ACDC"))),
                new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("01F2960B44B6846AE20FD4169D599D9F1C405A6CB1CBAA5B3179A06B3D1DB92166"))),
            }.ToArray()), "Invalid location pointer.");

            Assert.AreEqual(9, AggregationHashChain.CalcLocationPointer(new List<AggregationHashChain.Link>
            {
                new AggregationHashChain.Link(LinkDirection.Left, new AggregationHashChain.Metadata("test client", "test machine id")),
                new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("01404572B3A03FCBB57D265903A153B24237F277723D1B24A199F9F009A4EB23BE"))),
                new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("0160D25FD6F2A962B41F20CFC2DD9CC62C9C802EADB08E8F15E60D0316E778ACDC"))),
            }.ToArray()), "Invalid location pointer.");
        }

        [Test]
        public void AggregationHashChainLinkSequenceNumberTest()
        {
            AggregationHashChain.Link aggregationHashChain =
                new AggregationHashChain.Link(LinkDirection.Left, "test client", "test machine id", 1, 2);

            AggregationHashChain.Metadata metadata = aggregationHashChain.Metadata;

            Assert.AreEqual(1, metadata.SequenceNumber, "Aggregation hash chain link metadata sequnece number should match");
            Assert.AreEqual(2, metadata.RequestTime, "Aggregation hash chain link metadata request time should match");
        }

        [Test]
        public void AggregationHashChainLinkSequenceNumberMissingTest()
        {
            AggregationHashChain.Link aggregationHashChain = new AggregationHashChain.Link(LinkDirection.Left, new AggregationHashChain.Metadata("test client"));

            AggregationHashChain.Metadata metadata = aggregationHashChain.Metadata;

            Assert.IsNull(metadata.MachineId, "Aggregation hash chain link machine id should match");
            Assert.IsNull(metadata.SequenceNumber, "Aggregation hash chain link metadata sequnece number should match");
            Assert.IsNull(metadata.RequestTime, "Aggregation hash chain link metadata request time should match");
        }

        [Test]
        public void AggregationHashChainLinkMissingSiblingHashTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new AggregationHashChain.Link(LinkDirection.Left, (DataHash)null);
            });

            Assert.AreEqual("siblingHash", ex.ParamName);
        }

        [Test]
        public void AggregationHashChainLinkMissingMetadataTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new AggregationHashChain.Link(LinkDirection.Left, (AggregationHashChain.Metadata)null);
            });

            Assert.AreEqual("metadata", ex.ParamName);
        }

        [Test]
        public void AggregationHashChainLinkMissingClientIdTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new AggregationHashChain.Link(LinkDirection.Left, (string)null);
            });

            Assert.AreEqual("clientId", ex.ParamName);
        }

        [Test]
        public void TestGetLocationPointerWithMixedAggregationChains()
        {
            IKsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_With_Mixed_Aggregation_Chains);
            ReadOnlyCollection<AggregationHashChain> hashChains = signature.GetAggregationHashChains();
            ulong[] index = hashChains[0].GetChainIndex();
            int i = index.Length - 1;

            foreach (AggregationHashChain chain in hashChains)
            {
                ReadOnlyCollection<AggregationHashChain.Link> links = chain.GetChainLinks();
                Assert.AreEqual(index[i--], AggregationHashChain.CalcLocationPointer(links.ToArray()), "Location pointers do not match.");
            }
        }

        [Test]
        public void TestAggregationHashChainOkMissingOptionals()
        {
            AggregationHashChain aggregationHashChain = GetAggregationHashChainFromFile(Resources.AggregationHashChain_Ok_Missing_Optionals);
            Assert.AreEqual(8, aggregationHashChain.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestAggregationHashChainInvalidExtraTag()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Extra_Tag);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Unknown tag"));
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingAggregationAlgorithm()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Missing_Aggregation_Algorithm);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one algorithm must exist in aggregation hash chain"));
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingAggregationTime()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Missing_Aggregation_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one aggregation time must exist in aggregation hash chain"));
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingChainIndex()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Missing_Chain_Index);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Chain index is missing in aggregation hash chain"));
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingInputHash()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Missing_Input_Hash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one input hash must exist in aggregation hash chain"));
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingLinks()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Missing_Links);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Links are missing in aggregation hash chain"));
        }

        [Test]
        public void TestAggregationHashChainInvalidMultipleAggregationAlgorithm()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Multiple_Aggregation_Algorithm);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one algorithm must exist in aggregation hash chain"));
        }

        [Test]
        public void TestAggregationHashChainInvalidMultipleAggregationTime()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Multiple_Aggregation_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one aggregation time must exist in aggregation hash chain"));
        }

        [Test]
        public void TestAggregationHashChainInvalidMultipleInputData()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Multiple_Input_Data);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one input data value is allowed in aggregation hash chain"));
        }

        [Test]
        public void TestAggregationHashChainInvalidMultipleInputHash()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Multiple_Input_Hash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one input hash must exist in aggregation hash chain"));
        }

        [Test]
        public void TestAggregationHashChainInvalidType()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Invalid_Type);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Invalid tag type! Class: AggregationHashChain; Type: 0x802;"));
        }

        [Test]
        public void TestAggregationHashChainLinkOkMissingOptionals()
        {
            GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Ok_Missing_Optionals);
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidAllTagsDefined()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_All_Tags_Defined);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link"));
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidEmpty()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_Empty);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link"));
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidExtraTag()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_Extra_Tag);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Unknown tag"));
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMetadataMetahashNoSiblingHash()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_Metadata_Metahash_No_SiblingHash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link"));
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMultipleLevelCorrection()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_Multiple_LevelCorrection);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one levelcorrection value is allowed in aggregation hash chain link"));
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMultipleMetadata()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_Multiple_Metadata);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link"));
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMultipleMetahash()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_Multiple_Metahash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link"));
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMultipleSiblinghash()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_Multiple_Siblinghash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link"));
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidSiblinghashMetadataNoMetahash()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_SiblingHash_Metadata_No_MetaHash);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link"));
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidSiblinghashMetahashNoMetadata()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Link_Invalid_SiblingHash_MetaHash_No_Metadata);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one of three from sibling hash, legacy id or metadata must exist in aggregation hash chain link"));
        }

        [Test]
        public void TestAggregationHashChainMetadataOkMissingOptionals()
        {
            GetAggregationHashChainFromFile(Resources.AggregationHashChain_Metadata_Ok_Missing_Optionals);
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidExtraTag()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Metadata_Invalid_Extra_Tag);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Unknown tag"));
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMissingClientId()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Metadata_Invalid_Missing_Client_id);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one client id must exist in aggregation hash chain link metadata"));
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMultipleClientId()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Metadata_Invalid_Multiple_Client_Id);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Exactly one client id must exist in aggregation hash chain link metadata"));
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMultipleMachineId()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Metadata_Invalid_Multiple_Machine_Id);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one machine id is allowed in aggregation hash chain link metadata"));
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMultipleRequestTime()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Metadata_Invalid_Multiple_Request_Time);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one request time is allowed in aggregation hash chain link metadata"));
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMultipleSequenceNumber()
        {
            Assert.That(delegate
            {
                GetAggregationHashChainFromFile(Resources.AggregationHashChain_Metadata_Invalid_Multiple_Sequence_Number);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one sequence number is allowed in aggregation hash chain link metadata"));
        }

        [Test]
        public void ToStringTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type linkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Metadata");

            AggregationHashChain tag = TestUtil.GetCompositeTag<AggregationHashChain>(Constants.AggregationHashChain.TagType,
                new ITlvTag[]
                {
                    new IntegerTag(Constants.AggregationHashChain.AggregationTimeTagType, false, false, 1),
                    new IntegerTag(Constants.AggregationHashChain.ChainIndexTagType, false, false, 0),
                    new RawTag(Constants.AggregationHashChain.InputDataTagType, false, false, new byte[] { 0x1 }),
                    new ImprintTag(Constants.AggregationHashChain.InputHashTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                    new IntegerTag(Constants.AggregationHashChain.AggregationAlgorithmIdTagType, false, false, 1),
                    TestUtil.GetCompositeTag(linkType, (uint)LinkDirection.Left,
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
                });

            AggregationHashChain tag2 = new AggregationHashChain(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        [Test]
        public void LegacyIdValidTest()
        {
            LegacyIdTest(new byte[] { 3, 0, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0 });
        }

        [Test]
        public void LegacyIdInvalidFirstOctetTest()
        {
            Assert.That(delegate
            {
                LegacyIdTest(new byte[] { 2, 0, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0 });
            }, Throws.Exception.InnerException.TypeOf<TlvException>().With.InnerException.Message.StartWith("Invalid first octet in legacy id tag"));
        }

        [Test]
        public void LegacyIdInvalidTagLengthTooShortTest()
        {
            Assert.That(delegate
            {
                LegacyIdTest(new byte[] { 3, 0, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 0 });
            }, Throws.Exception.InnerException.TypeOf<TlvException>().With.InnerException.Message.StartWith("Invalid legacy id tag length"));
        }

        [Test]
        public void LegacyIdInvalidTagLengthTooLongTest()
        {
            Assert.That(delegate
            {
                LegacyIdTest(new byte[] { 3, 0, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 0 });
            }, Throws.Exception.InnerException.TypeOf<TlvException>().With.InnerException.Message.StartWith("Invalid legacy id tag length"));
        }

        [Test]
        public void LegacyIdInvalidLengthValueTest()
        {
            Assert.That(delegate
            {
                LegacyIdTest(new byte[] { 3, 0, 26, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0 });
            }, Throws.Exception.InnerException.TypeOf<TlvException>().With.InnerException.Message.StartWith("Invalid legacy id length value"));
        }

        [Test]
        public void LegacyIdInvalidPaddingTest1()
        {
            Assert.That(delegate
            {
                LegacyIdTest(new byte[] { 3, 0, 24, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0 });
            }, Throws.Exception.InnerException.TypeOf<TlvException>().With.InnerException.Message.StartWith("Invalid padding octet."));
        }

        [Test]
        public void LegacyIdInvalidPaddingTest2()
        {
            Assert.That(delegate
            {
                LegacyIdTest(new byte[] { 3, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
            }, Throws.Exception.InnerException.TypeOf<TlvException>().With.InnerException.Message.StartWith("Invalid padding octet."));
        }

        [Test]
        public void LegacyIdInvalidUtf8CodeTest()
        {
            Assert.That(delegate
            {
                LegacyIdTest(new byte[] { 3, 0, 25, 0x00, 0x80, 0x02, 0xFE, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0 });
            }, Throws.Exception.InnerException.TypeOf<DecoderFallbackException>());
        }

        public void LegacyIdTest(byte[] legacyIdValue)
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type linkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");

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
                    TestUtil.GetCompositeTag(linkType, (uint)LinkDirection.Left,
                        new ITlvTag[]
                        {
                            new IntegerTag(Constants.AggregationHashChain.Link.LevelCorrectionTagType, false, false, 0),
                            new RawTag(Constants.AggregationHashChain.Link.LegacyId, false, false,
                                legacyIdValue),
                        })
                });
        }

        private static AggregationHashChain GetAggregationHashChainFromFile(string file)
        {
            return new AggregationHashChain(TestUtil.GetRawTag(file));
        }
    }
}