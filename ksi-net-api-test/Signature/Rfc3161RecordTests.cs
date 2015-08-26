using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class Rfc3161RecordTests
    {

        [Test]
        public void TestRfc3161RecordOk()
        {
            Rfc3161Record rfc3161Record = GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Ok);
            Assert.AreEqual(10, rfc3161Record.Count, "Invalid amount of child TLV objects");
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid RFC 3161 record type: 2055")]
        public void TestRfc3161RecordInvalidType()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Type);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestRfc3161RecordInvalidExtraTag()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Extra_Tag);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMissingAggregationTime()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Aggregation_Time);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Chain indexes must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMissingChainIndex()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Chain_Index);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMissingInputHash()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Input_Hash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signed attributes algorithm must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMissingSignedAttributesAlgorithm()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Signed_Attributes_Algorithm);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signed attributes prefix must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMissingSignedAttributesPrefix()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Signed_Attributes_Prefix);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signed attributes suffix must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMissingSignedAttributesSuffix()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Signed_Attributes_Suffix);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one tstInfo algorithm must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMissingTstInfoAlgorithm()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_TstInfo_Algorithm);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one tstInfo prefix must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMissingTstInfoPrefix()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_TstInfo_Prefix);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one tstInfo suffix must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMissingTstInfoSuffix()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_TstInfo_Suffix);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMultipleAggregationTime()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Aggregation_Time);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMultipleInputHash()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Input_Hash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signed attributes algorithm must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMultipleSignedAttributesAlgorithm()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Signed_Attributes_Algorithm);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signed attributes prefix must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMultipleSignedAttributesPrefix()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Signed_Attributes_Prefix);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signed attributes suffix must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMultipleSignedAttributesSuffix()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Signed_Attributes_Suffix);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one tstInfo algorithm must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMultipleTstInfoAlgorithm()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_TstInfo_Algorithm);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one tstInfo prefix must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMultipleTstInfoPrefix()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_TstInfo_Prefix);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one tstInfo suffix must exist in RFC 3161 record")]
        public void TestRfc3161RecordInvalidMultipleTstInfoSuffix()
        {
            GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_TstInfo_Suffix);
        }

        private Rfc3161Record GetRfc3161RecordFromFile(string file)
        {
            using (var stream = new FileStream(file, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                Rfc3161Record rfc3161Record = new Rfc3161Record(reader.ReadTag());

                return rfc3161Record;
            }
        }
    }
}
