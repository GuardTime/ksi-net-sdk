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

        [Test]
        public void TestKsiSignatureDoInvalidType()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Type);
            }, "Invalid signature type: 2201");
            
        }

        [Test]
        public void TestKsiSignatureDoInvalidContainsPublicationRecordAndCalendarAuthenticationRecord()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Contain_Publication_Record_And_Calendar_Authentication_Record);
            }, "Only one from publication record or calendar authentication record is allowed in signature data object");
            
        }

        [Test]
        public void TestKsiSignatureDoInvalidExtraTag()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Extra_Tag);
            }, "Invalid tag");
            
        }

        [Test]
        public void TestKsiSignatureDoInvalidMissingAggregationHashChain()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Missing_Aggregation_Hash_Chain);
            }, "Aggregation hash chains must exist in signature data object");
            
        }

        [Test]
        public void TestKsiSignatureDoInvalidMissingCalendarHashChain()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Missing_Calendar_Hash_Chain);
            }, "No publication record or calendar authentication record is allowed in signature data object if there is no calendar hash chain");
            
        }

        

        [Test]
        public void TestKsiSignatureDoInvalidMultipleCalendarAuthenticationRecords()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Calendar_Authentication_Records);
            }, "Only one from publication record or calendar authentication record is allowed in signature data object");
            
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultipleCalendarHashChain()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Calendar_Hash_Chains);
            }, "Only one calendar hash chain is allowed in signature data object");
            
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultiplePublicationRecords()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Publication_Records);
            }, "Only one from publication record or calendar authentication record is allowed in signature data object");
            
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultipleRfc3161Records()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Rfc_3161_Records);
            }, "Only one RFC 3161 record is allowed in signature data object");
            
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