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
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Ok, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
                Assert.AreEqual(5, aggregationAuthenticationRecord.Count, "Invalid amount of child TLV objects");
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestAggregationAuthenticationRecordInvalidExtraTag()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Invalid_Extra_Tag, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMissingAggregationTime()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Aggregation_Time, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Chain indexes must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMissingChainIndex()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Chain_Index, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMissingInputHash()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Input_Hash, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature data must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMissingSignatureData()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Signature_Data, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMultipleAggregationTime()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Invalid_Multiple_Aggregation_Time, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMultipleInputHash()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Invalid_Multiple_Input_Hash, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature data must exist in aggregation authentication record")]
        public void TestAggregationAuthenticationRecordInvalidMultipleSignatureData()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Invalid_Multiple_Signature_Data, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid aggregation authentication record type: 2053")]
        public void TestAggregationAuthenticationRecordInvalidType()
        {
            using (var stream = new FileStream(Properties.Resources.AggregationAuthenticationRecord_Invalid_Type, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());
                aggregationAuthenticationRecord.IsValidStructure();
            }
        }



    }
}
