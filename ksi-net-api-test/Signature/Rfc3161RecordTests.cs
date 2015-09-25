using System;
using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Utils;

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

            Assert.AreEqual(rfc3161Record.GetOutputHash(rfc3161Record.InputHash), new DataHash(HashAlgorithm.Sha2256, Base16.Decode("C96682043DB0474031CEF1AE12941523E59BDC64E62CDAAE817CE46370918648")), "Output hash should be correctly calculated");
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
