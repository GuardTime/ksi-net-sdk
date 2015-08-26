using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class CalendarHashChainTests
    {

        [Test]
        public void TestCalendarHashChainOk()
        {
            CalendarHashChain calendarHashChain = GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Ok);
            Assert.AreEqual(26, calendarHashChain.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestCalendarHashChainOkMissingOptionals()
        {
            CalendarHashChain calendarHashChain = GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Ok_Missing_Optionals);
            Assert.AreEqual(25, calendarHashChain.Count, "Invalid amount of child TLV objects");
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid calendar hash chain type: 2051")]
        public void TestCalendarHashChainInvalidType()
        {
            GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Type);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestCalendarHashChainInvalidExtraTag()
        {
            GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Extra_Tag);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in calendar hash chain")]
        public void TestCalendarHashChainInvalidMissingInputHash()
        {
            GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Missing_Input_Hash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Links are missing in calendar hash chain")]
        public void TestCalendarHashChainInvalidMissingLinks()
        {
            GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Missing_Links);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one publication time must exist in calendar hash chain")]
        public void TestCalendarHashChainInvalidMissingPublicationTime()
        {
            GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Missing_Publication_Time);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one aggregation time is allowed in calendar hash chain")]
        public void TestCalendarHashChainInvalidMultipleAggregationTime()
        {
            GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Multiple_Aggregation_Time);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one input hash must exist in calendar hash chain")]
        public void TestCalendarHashChainInvalidMultipleInputHash()
        {
            GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Multiple_Input_Hash);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one publication time must exist in calendar hash chain")]
        public void TestCalendarHashChainInvalidMultiplePublicationTime()
        {
            GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Multiple_Publication_Time);
        }

        private CalendarHashChain GetCalendarHashChainFromFile(string file)
        {
            using (var stream = new FileStream(file, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                CalendarHashChain calendarHashChain = new CalendarHashChain(reader.ReadTag());

                return calendarHashChain;
            }
        }
    }
}
