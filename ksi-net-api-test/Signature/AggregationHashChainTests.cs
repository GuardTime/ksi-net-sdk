using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;
using System;

namespace Guardtime.KSI.Signature
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

        private AggregationHashChain GetAggregationHashChainFromFile(string file)
        {
            using (var stream = new FileStream(file, FileMode.Open))
            {
                using (var reader = new TlvReader(stream))
                {
                    AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());

                    return aggregationHashChain;
                }
            }
        }
    }
}