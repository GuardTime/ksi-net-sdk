using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class AggregationAuthenticationRecordTests
    {

        [Test]
        public void TestAggregationAuthenticationRecordOk()
        {
            AggregationAuthenticationRecord aggregationAuthenticationRecord = GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Ok);
            Assert.AreEqual(5, aggregationAuthenticationRecord.Count, "Invalid amount of child TLV objects");
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestAggregationAuthenticationRecordInvalidExtraTag()
        {
            GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Extra_Tag);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMissingAggregationTime()
        {
            GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Aggregation_Time);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Chain indexes must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMissingChainIndex()
        {
            GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Chain_Index);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMissingInputHash()
        {
            GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Input_Hash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature data must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMissingSignatureData()
        {
            GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Signature_Data);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMultipleAggregationTime()
        {
            GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Multiple_Aggregation_Time);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMultipleInputHash()
        {
            GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Multiple_Input_Hash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature data must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMultipleSignatureData()
        {
            GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Multiple_Signature_Data);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid aggregation authentication record type: 2053")]
        public void TestAggregationAuthenticationRecordInvalidType()
        {
            GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Type);
        }

        private AggregationAuthenticationRecord GetAggregationAuthenticationRecordFromFile(string file)
        {
            using (var stream = new FileStream(file, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();

                return aggregationAuthenticationRecord;
            }
        }



    }
}
