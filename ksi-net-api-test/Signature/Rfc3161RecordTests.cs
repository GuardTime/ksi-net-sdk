using System;
using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;

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

            Assert.Throws<ArgumentNullException>(delegate
            {
                rfc3161Record.GetOutputHash(null);
            }, "Output hash calculation should throw exception when inputhash is null");

            Assert.AreEqual(rfc3161Record.GetOutputHash(rfc3161Record.InputHash), new DataHash(HashAlgorithm.Sha2256, new byte[] { 0x6D, 0x2B, 0x05, 0x79, 0xBA, 0x94, 0x7A, 0x38, 0x7F, 0x4F, 0xD7, 0x61, 0x9E, 0x6B, 0xDB, 0x04, 0xD3, 0x7C, 0x5A, 0x80, 0x63, 0x12, 0xA0, 0x93, 0x73, 0x31, 0xA9, 0x11, 0x5D, 0xD1, 0x9E, 0x3A }), "Output hash should be correctly calculated");
        }

        [Test]
        public void TestRfc3161RecordInvalidType()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Type);
            }, "Invalid RFC 3161 record type: 2055");
        }

        [Test]
        public void TestRfc3161RecordInvalidExtraTag()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Extra_Tag);
            }, "Invalid tag");
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingAggregationTime()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Aggregation_Time);
            }, "Only one aggregation time must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingChainIndex()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Chain_Index);
            }, "Chain indexes must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingInputHash()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Input_Hash);
            }, "Only one input hash must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingSignedAttributesAlgorithm()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Signed_Attributes_Algorithm);
            }, "Only one signed attributes algorithm must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingSignedAttributesPrefix()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Signed_Attributes_Prefix);
            }, "Only one signed attributes prefix must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingSignedAttributesSuffix()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_Signed_Attributes_Suffix);
            }, "Only one signed attributes suffix must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingTstInfoAlgorithm()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_TstInfo_Algorithm);
            }, "Only one tstInfo algorithm must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingTstInfoPrefix()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_TstInfo_Prefix);
            }, "Only one tstInfo prefix must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMissingTstInfoSuffix()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Missing_TstInfo_Suffix);
            }, "Only one tstInfo suffix must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleAggregationTime()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Aggregation_Time);
            }, "Only one aggregation time must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleInputHash()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Input_Hash);
            }, "Only one input hash must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleSignedAttributesAlgorithm()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Signed_Attributes_Algorithm);
            }, "Only one signed attributes algorithm must exist in RFC 3161 record");
            
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleSignedAttributesPrefix()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Signed_Attributes_Prefix);
            }, "Only one signed attributes prefix must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleSignedAttributesSuffix()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_Signed_Attributes_Suffix);
            }, "Only one signed attributes suffix must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleTstInfoAlgorithm()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_TstInfo_Algorithm);
            }, "Only one tstInfo algorithm must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleTstInfoPrefix()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_TstInfo_Prefix);
            }, "Only one tstInfo prefix must exist in RFC 3161 record");
        }

        [Test]
        public void TestRfc3161RecordInvalidMultipleTstInfoSuffix()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetRfc3161RecordFromFile(Properties.Resources.Rfc3161Record_Invalid_Multiple_TstInfo_Suffix);
            }, "Only one tstInfo suffix must exist in RFC 3161 record");
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
