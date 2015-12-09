using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class CalendarAuthenticationRecordTests
    {
        [Test]
        public void TestCalendarAuthenticationRecordOk()
        {
            CalendarAuthenticationRecord calendarAuthenticationRecord = GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Ok);
            Assert.AreEqual(2, calendarAuthenticationRecord.Count, "Invalid amount of child TLV objects");

            Assert.IsTrue(
                calendarAuthenticationRecord.PublicationData.Equals(new PublicationData(1398902400,
                    new DataHash(Base16.Decode("01C45A4D73815CBECD5493197513A6C2C9058B0B16B99A64805368A7186D528E8B")))));
            Assert.IsTrue(
                calendarAuthenticationRecord.SignatureData.Equals(
                    new SignatureData(new RawTag(0xb, false, false,
                        Base16.Decode(
                            "0116312E322E3834302E3131333534392E312E312E3131008002010098D9A4D14722BB2C22425AC9112FBF6A2491B7051AD0CBFD8153E669BFCC6CDF20EEC80F7FCC7236985A4F83871DD6E245470BCA323A3902035B78764DDC4C6EB42416A3A7D7E5CEF6ED6AE8FADA668413758CF7DE1E9565EDF646170286D0F43CA30491DD3407B53DEEDDCBD2620057AB6580E3D3E938AE44EABAF3282357EEBB7B2325616755A1F20B3A78DE2F636DE10F7CCD75B6C5BB80EFEBA216F9BF1A302DCB93B9D3E3E9754620E6D8EC8672C5329CBBB00A9A4617242950D68B8A55CBA77E69DECDD49DD96F69FAA6BFBB0EF48A913F5F26AFA01FB08192D62123FC644BA2978CAF147229BD5702663494983A40ED77AA5016EAABC1FE8456DC17D40304C246B139")))));
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidExtraTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Extra_Tag);
            }, "Invalid tag");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidMissingPublicationData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Missing_Publication_Data);
            }, "Only one publication data must exist in calendar authentication record");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidMissingSignatureData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Missing_Signature_Data);
            }, "Only one signature data must exist in calendar authentication record");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidMultiplePublicationData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Multiple_Publication_Data);
            }, "Only one publication data must exist in calendar authentication record");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidMultipleSignatureData()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Multiple_Signature_Data);
            }, "Only one signature data must exist in calendar authentication record");
        }

        [Test]
        public void TestCalendarAuthenticationRecordInvalidType()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Type);
            }, "Invalid calendar authentication record type: 2054");
        }

        private static CalendarAuthenticationRecord GetCalendarAuthenticationRecordFromFile(string file)
        {
            using (TlvReader reader = new TlvReader(new FileStream(file, FileMode.Open)))
            {
                CalendarAuthenticationRecord calendarAuthenticationRecord = new CalendarAuthenticationRecord(reader.ReadTag());

                return calendarAuthenticationRecord;
            }
        }
    }
}