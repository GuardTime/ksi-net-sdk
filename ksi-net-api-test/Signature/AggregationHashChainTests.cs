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
using Guardtime.KSI.Signature;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class AggregationHashChainTests
    {
        [Test]
        public void TestAggregationHashChainOk()
        {
            AggregationHashChain aggregationHashChain = GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Ok);
            Assert.AreEqual(9, aggregationHashChain.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestAggregationHashChainOkMissingOptionals()
        {
            AggregationHashChain aggregationHashChain = GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Ok_Missing_Optionals);
            Assert.AreEqual(8, aggregationHashChain.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestAggregationHashChainInvalidExtraTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Extra_Tag);
            }, "Invalid tag");
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingAggregationAlgorithm()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Aggregation_Algorithm);
            }, "Only one algorithm must exist in aggregation hash chain");
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingAggregationTime()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Aggregation_Time);
            }, "Only one aggregation time must exist in aggregation hash chain");
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingChainIndex()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Chain_Index);
            }, "Chain index is missing in aggregation hash chain");
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingInputHash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Input_Hash);
            }, "Only one input hash must exist in aggregation hash chain");
        }

        [Test]
        public void TestAggregationHashChainInvalidMissingLinks()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Links);
            }, "Links are missing in aggregation hash chain");
        }

        [Test]
        public void TestAggregationHashChainInvalidMultipleAggregationAlgorithm()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Multiple_Aggregation_Algorithm);
            }, "Only one algorithm must exist in aggregation hash chain");
        }

        [Test]
        public void TestAggregationHashChainInvalidMultipleAggregationTime()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Multiple_Aggregation_Time);
            }, "Only one aggregation time must exist in aggregation hash chain");
        }

        [Test]
        public void TestAggregationHashChainInvalidMultipleInputData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Multiple_Input_Data);
            }, "Only one input data value is allowed in aggregation hash chain");
        }

        [Test]
        public void TestAggregationHashChainInvalidMultipleInputHash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Multiple_Input_Hash);
            }, "Only one input hash must exist in aggregation hash chain");
        }

        [Test]
        public void TestAggregationHashChainInvalidType()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Type);
            }, "Invalid aggregation hash chain type: 2050");
        }

        [Test]
        public void TestAggregationHashChainLinkOkMissingOptionals()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Ok_Missing_Optionals);
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidAllTagsDefined()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_All_Tags_Defined);
            }, "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidEmpty()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Empty);
            }, "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidExtraTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Extra_Tag);
            }, "Invalid tag");
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMetadataMetahashNoSiblingHash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Metadata_Metahash_No_SiblingHash);
            }, "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMultipleLevelCorrection()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_LevelCorrection);
            }, "Only one levelcorrection value is allowed in aggregation hash chain link");
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMultipleMetadata()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_Metadata);
            }, "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMultipleMetahash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_Metahash);
            }, "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidMultipleSiblinghash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_Siblinghash);
            }, "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidSiblinghashMetadataNoMetahash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_SiblingHash_Metadata_No_MetaHash);
            }, "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
        }

        [Test]
        public void TestAggregationHashChainLinkInvalidSiblinghashMetahashNoMetadata()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_SiblingHash_MetaHash_No_Metadata);
            }, "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link");
        }

        [Test]
        public void TestAggregationHashChainMetadataOkMissingOptionals()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Ok_Missing_Optionals);
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidExtraTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Extra_Tag);
            }, "Invalid tag");
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMissingClientId()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Missing_Client_id);
            }, "Only one client id must exist in aggregation hash chain link metadata");
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMultipleClientId()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Client_Id);
            }, "Only one client id must exist in aggregation hash chain link metadata");
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMultipleMachineId()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Machine_Id);
            }, "Only one machine id is allowed in aggregation hash chain link metadata");
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMultipleRequestTime()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Request_Time);
            }, "Only one request time is allowed in aggregation hash chain link metadata");
        }

        [Test]
        public void TestAggregationHashChainMetadataInvalidMultipleSequenceNumber()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Sequence_Number);
            }, "Only one sequence number is allowed in aggregation hash chain link metadata");
        }

        [Test]
        public void ToStringTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type linkType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+Link");
            Type metadataType = assembly.GetType("Guardtime.KSI.Signature.AggregationHashChain+MetaData");

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
                });

            AggregationHashChain tag2 = new AggregationHashChain(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        private static AggregationHashChain GetAggregationHashChainFromFile(string file)
        {
            using (TlvReader reader = new TlvReader(new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open)))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());

                return aggregationHashChain;
            }
        }
    }
}