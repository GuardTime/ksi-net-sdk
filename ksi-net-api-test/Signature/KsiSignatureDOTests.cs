using System;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using NUnit.Framework;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class KsiSignatureDoTests
    {
        [Test]
        public void TestKsiSignatureDoOk()
        {
            KsiSignatureDo signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok);
            Assert.AreEqual(5, signature.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestKsiSignatureDoOkMissingCalendarHashChain()
        {
            KsiSignatureDo signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_Missing_Calendar_Hash_Chain);
            Assert.AreEqual(3, signature.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestKsiSignatureDoOkMissingPublicationRecord()
        {
            KsiSignatureDo signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record);
            Assert.AreEqual(4, signature.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestLegacyKsiSignatureDoOk()
        {
            KsiSignatureDo signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Legacy_Ok);
            Assert.AreEqual(4, signature.Count, "Invalid amount of child TLV objects");
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid signature type: 2201")]
        public void TestKsiSignatureDoInvalidType()
        {
            GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Type);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one from publication record or calendar authentication record is allowed in signature data object")]
        public void TestKsiSignatureDoInvalidContainsPublicationRecordAndCalendarAuthenticationRecord()
        {
            GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Contain_Publication_Record_And_Calendar_Authentication_Record);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestKsiSignatureDoInvalidExtraTag()
        {
            GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Extra_Tag);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Aggregation hash chains must exist in signature data object")]
        public void TestKsiSignatureDoInvalidMissingAggregationHashChain()
        {
            GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Missing_Aggregation_Hash_Chain);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "No publication record or calendar authentication record is allowed in signature data object if there is no calendar hash chain")]
        public void TestKsiSignatureDoInvalidMissingCalendarHashChain()
        {
            GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Missing_Calendar_Hash_Chain);
        }

        

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one from publication record or calendar authentication record is allowed in signature data object")]
        public void TestKsiSignatureDoInvalidMultipleCalendarAuthenticationRecords()
        {
            GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Calendar_Authentication_Records);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one calendar hash chain is allowed in signature data object")]
        public void TestKsiSignatureDoInvalidMultipleCalendarHashChain()
        {
            GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Calendar_Hash_Chains);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one from publication record or calendar authentication record is allowed in signature data object")]
        public void TestKsiSignatureDoInvalidMultiplePublicationRecords()
        {
            GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Publication_Records);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one RFC 3161 record is allowed in signature data object")]
        public void TestKsiSignatureDoInvalidMultipleRfc3161Records()
        {
            GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Rfc_3161_Records);
        }

        // TODO: Multiple aggregation authentication record test is missing

        private KsiSignatureDo GetKsiSignatureDoFromFile(string file)
        {
            using (var stream = new FileStream(file, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                return new KsiSignatureDo(reader.ReadTag());
            }
        }
    }
}