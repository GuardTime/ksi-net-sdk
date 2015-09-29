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

        [Test]
        public void TestCalendarHashChainInvalidType()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Type);
            }, "Invalid calendar hash chain type: 2051");
            
        }

        [Test]
        public void TestCalendarHashChainInvalidExtraTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Extra_Tag);
            }, "Invalid tag");
            
        }

        [Test]
        public void TestCalendarHashChainInvalidMissingInputHash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Missing_Input_Hash);
            }, "Only one input hash must exist in calendar hash chain");
            
        }

        [Test]
        public void TestCalendarHashChainInvalidMissingLinks()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Missing_Links);
            }, "Links are missing in calendar hash chain");
            
        }

        [Test]
        public void TestCalendarHashChainInvalidMissingPublicationTime()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Missing_Publication_Time);
            }, "Only one publication time must exist in calendar hash chain");
            
        }

        [Test]
        public void TestCalendarHashChainInvalidMultipleAggregationTime()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Multiple_Aggregation_Time);
            }, "Only one aggregation time is allowed in calendar hash chain");
            
        }

        [Test]
        public void TestCalendarHashChainInvalidMultipleInputHash()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Multiple_Input_Hash);
            }, "Only one input hash must exist in calendar hash chain");
            
        }

        [Test]
        public void TestCalendarHashChainInvalidMultiplePublicationTime()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetCalendarHashChainFromFile(Properties.Resources.CalendarHashChain_Invalid_Multiple_Publication_Time);
            }, "Only one publication time must exist in calendar hash chain");
            
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
