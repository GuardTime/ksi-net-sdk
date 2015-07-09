using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

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
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestCalendarAuthenticationRecordInvalidExtraTag()
        {
            GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Extra_Tag);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one publication data must exist in calendar authentication record")]
        public void TestCalendarAuthenticationRecordInvalidMissingPublicationData()
        {
            GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Missing_Publication_Data);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature data must exist in calendar authentication record")]
        public void TestCalendarAuthenticationRecordInvalidMissingSignatureData()
        {
            GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Missing_Signature_Data);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one publication data must exist in calendar authentication record")]
        public void TestCalendarAuthenticationRecordInvalidMultiplePublicationData()
        {
            GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Multiple_Publication_Data);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature data must exist in calendar authentication record")]
        public void TestCalendarAuthenticationRecordInvalidMultipleSignatureData()
        {
            GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Multiple_Signature_Data);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid calendar authentication record type: 2054")]
        public void TestCalendarAuthenticationRecordInvalidType()
        {
            GetCalendarAuthenticationRecordFromFile(Properties.Resources.CalendarAuthenticationRecord_Invalid_Type);
        }

        private CalendarAuthenticationRecord GetCalendarAuthenticationRecordFromFile(string file)
        {
            using (var stream = new FileStream(file, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                CalendarAuthenticationRecord calendarAuthenticationRecord = new CalendarAuthenticationRecord(reader.ReadTag());
                calendarAuthenticationRecord.IsValidStructure();

                return calendarAuthenticationRecord;
            }
        }



    }
}
