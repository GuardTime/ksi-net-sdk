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

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestAggregationHashChainInvalidExtraTag()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Extra_Tag);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one algorithm must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingAggregationAlgorithm()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Aggregation_Algorithm);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingAggregationTime()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Aggregation_Time);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Chain index is missing in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingChainIndex()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Chain_Index);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingInputHash()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Input_Hash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Links are missing in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingLinks()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Missing_Links);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one algorithm must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMultipleAggregationAlgorithm()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Multiple_Aggregation_Algorithm);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMultipleAggregationTime()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Multiple_Aggregation_Time);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input data value is allowed in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMultipleInputData()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Multiple_Input_Data);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMultipleInputHash()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Multiple_Input_Hash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid aggregation hash chain type: 2050")]
        public void TestAggregationHashChainInvalidType()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Invalid_Type);
        }

        [Test]
        public void TestAggregationHashChainLinkOkMissingOptionals()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Ok_Missing_Optionals);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidAllTagsDefined()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_All_Tags_Defined);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidEmpty()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Empty);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestAggregationHashChainLinkInvalidExtraTag()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Extra_Tag);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMetadataMetahashNoSiblingHash()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Metadata_Metahash_No_SiblingHash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one levelcorrection value is allowed in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMultipleLevelCorrection()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_LevelCorrection);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMultipleMetadata()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_Metadata);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMultipleMetahash()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_Metahash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMultipleSiblinghash()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_Siblinghash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidSiblinghashMetadataNoMetahash()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_SiblingHash_Metadata_No_MetaHash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidSiblinghashMetahashNoMetadata()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Link_Invalid_SiblingHash_MetaHash_No_Metadata);
        }

        [Test]
        public void TestAggregationHashChainMetadataOkMissingOptionals()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Ok_Missing_Optionals);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestAggregationHashChainMetadataInvalidExtraTag()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Extra_Tag);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one client id must exist in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMissingClientId()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Missing_Client_id);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one client id must exist in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMultipleClientId()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Client_Id);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one machine id is allowed in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMultipleMachineId()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Machine_Id);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one request time is allowed in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMultipleRequestTime()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Request_Time);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one sequence number is allowed in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMultipleSequenceNumber()
        {
            GetAggregationHashChainFromFile(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Sequence_Number);
        }

        private AggregationHashChain GetAggregationHashChainFromFile(string file)
        {
            using (var stream = new FileStream(file, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());

                return aggregationHashChain;
            }
        }



    }
}
