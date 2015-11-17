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

        [Test]
        public void TestAggregationAuthenticationRecordInvalidExtraTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Extra_Tag);
            }, "Invalid tag");
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMissingAggregationTime()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Aggregation_Time);
            }, "Only one aggregation time must exist in aggregation authentication record");
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMissingChainIndex()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Chain_Index);
            }, "Chain indexes must exist in aggregation authentication record");
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMissingInputHash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Input_Hash);
            }, "Only one input hash must exist in aggregation authentication record");
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMissingSignatureData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Missing_Signature_Data);
            }, "Only one signature data must exist in aggregation authentication record");
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMultipleAggregationTime()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Multiple_Aggregation_Time);
            }, "Only one aggregation time must exist in aggregation authentication record");
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMultipleInputHash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Multiple_Input_Hash);
            }, "Only one input hash must exist in aggregation authentication record");
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidMultipleSignatureData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Multiple_Signature_Data);
            }, "Only one signature data must exist in aggregation authentication record");
        }

        [Test]
        public void TestAggregationAuthenticationRecordInvalidType()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetAggregationAuthenticationRecordFromFile(Properties.Resources.AggregationAuthenticationRecord_Invalid_Type);
            }, "Invalid aggregation authentication record type: 2053");
        }

        private static AggregationAuthenticationRecord GetAggregationAuthenticationRecordFromFile(string file)
        {
            using (FileStream stream = new FileStream(file, FileMode.Open))
            {
                using (TlvReader reader = new TlvReader(stream))
                {
                    AggregationAuthenticationRecord aggregationAuthenticationRecord = new AggregationAuthenticationRecord(reader.ReadTag());

                    return aggregationAuthenticationRecord;
                }
            }
        }
    }
}