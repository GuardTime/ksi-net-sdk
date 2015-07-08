using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class AggregationHashChainTests
    {

        [Test]
        public void TestAggregationHashChainOk()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Ok, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
                Assert.AreEqual(9, aggregationHashChain.Count, "Invalid amount of child TLV objects");
            }
        }

        [Test]
        public void TestAggregationHashChainOkMissingOptionals()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Ok_Missing_Optionals, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
                Assert.AreEqual(8, aggregationHashChain.Count, "Invalid amount of child TLV objects");
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestAggregationHashChainInvalidExtraTag()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Extra_Tag, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one algorithm must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingAggregationAlgorithm()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Missing_Aggregation_Algorithm, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingAggregationTime()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Missing_Aggregation_Time, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Chain index is missing in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingChainIndex()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Missing_Chain_Index, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingInputHash()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Missing_Input_Hash, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Links are missing in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMissingLinks()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Missing_Links, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one algorithm must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMultipleAggregationAlgorithm()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Multiple_Aggregation_Algorithm, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMultipleAggregationTime()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Multiple_Aggregation_Time, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input data value is allowed in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMultipleInputData()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Multiple_Input_Data, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in aggregation hash chain")]
        public void TestAggregationHashChainInvalidMultipleInputHash()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Multiple_Input_Hash, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid aggregation hash chain type: 2050")]
        public void TestAggregationHashChainInvalidType()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Invalid_Type, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test]
        public void TestAggregationHashChainLinkOkMissingOptionals()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Ok_Missing_Optionals, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidAllTagsDefined()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_All_Tags_Defined, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidEmpty()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_Empty, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestAggregationHashChainLinkInvalidExtraTag()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_Extra_Tag, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMetadataMetahashNoSiblingHash()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_Metadata_Metahash_No_SiblingHash, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one levelcorrection value is allowed in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMultipleLevelCorrection()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_LevelCorrection, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMultipleMetadata()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_Metadata, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMultipleMetahash()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_Metahash, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidMultipleSiblinghash()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_Multiple_Siblinghash, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidSiblinghashMetadataNoMetahash()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_SiblingHash_Metadata_No_MetaHash, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one of three from siblinghash, metahash or metadata must exist in aggregation hash chain link")]
        public void TestAggregationHashChainLinkInvalidSiblinghashMetahashNoMetadata()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Link_Invalid_SiblingHash_MetaHash_No_Metadata, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test]
        public void TestAggregationHashChainMetadataOkMissingOptionals()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Metadata_Ok_Missing_Optionals, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestAggregationHashChainMetadataInvalidExtraTag()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Metadata_Invalid_Extra_Tag, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one client id must exist in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMissingClientId()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Metadata_Invalid_Missing_Client_id, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one client id must exist in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMultipleClientId()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Client_Id, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one machine id is allowed in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMultipleMachineId()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Machine_Id, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one request time is allowed in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMultipleRequestTime()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Request_Time, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one sequence number is allowed in aggregation hash chain link metadata")]
        public void TestAggregationHashChainMetadataInvalidMultipleSequenceNumber()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationHashChain_Metadata_Invalid_Multiple_Sequence_Number, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationHashChain aggregationHashChain = new AggregationHashChain(reader.ReadTag());
                aggregationHashChain.IsValidStructure();
            }
        }



    }
}
