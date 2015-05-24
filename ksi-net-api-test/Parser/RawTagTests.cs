using System;
using NUnit.Framework;

namespace Guardtime.KSI.Parser
{
    [TestFixture]
    public class RawTagTests
    {

        [Test]
        public void TestTlvTagCreateFromData()
        {
            var tag = new RawTag(0x1, true, true, new byte[] {0x1, 0x2, 0x3});
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be preserved");
            Assert.IsTrue(tag.NonCritical, "Tag non critical flag should be preserved");
            Assert.IsTrue(tag.Forward, "Tag forward flag should be preserved");
            CollectionAssert.AreEqual(new byte[] {0x1, 0x2, 0x3}, tag.Value, "Tag value should be preserved");
            Assert.AreEqual("TLV[0x1,N,F]:0x010203", tag.ToString());
        }

        [Test]
        public void TestTlvTagCreateFromTag()
        {
            var tlvTag = new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x3 });
            var tag = new RawTag(tlvTag);
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new byte[] { 0x1, 0x2, 0x3 }, tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:0x010203", tag.ToString(), "Tag string representation should be correct");

            Assert.AreEqual(new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x3 }), tag, "Tag Equals function should compare correctly");
        }

        [Test, ExpectedException(typeof(ArgumentNullException))]
        public void TestTlvTagCreateFromNullData()
        {
            var tag = new RawTag(0x1, false, false, null);
        }

        [Test, ExpectedException(typeof(ArgumentNullException))]
        public void TestTlvTagCreateFromNullTag()
        {
            var tag = new RawTag((TlvTag)null);
        }
    }
}
