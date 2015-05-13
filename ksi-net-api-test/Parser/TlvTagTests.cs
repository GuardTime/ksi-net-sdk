using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Parser
{
    [TestClass]
    public class TlvTagTests
    {

        [TestMethod]
        public void TestTlvTagCreateFromData()
        {
            var tag = new TlvTag(0x1, true, true, new byte[] {0x1, 0x2, 0x3});
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be preserved");
            Assert.IsTrue(tag.NonCritical, "Tag non critical flag should be preserved");
            Assert.IsTrue(tag.Forward, "Tag forward flag should be preserved");
            CollectionAssert.AreEqual(new byte[] {0x1, 0x2, 0x3}, tag.Value, "Tag value should be preserved");
            Assert.AreEqual("TLV[0x1,N,F]:0x010203", tag.ToString());
        }

        [TestMethod]
        public void TestTlvTagCreateFromTag()
        {
            var tlvTag = new TlvTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x3 });
            var tag = new TlvTag(tlvTag);
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new byte[] { 0x1, 0x2, 0x3 }, tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:0x010203", tag.ToString(), "Tag string representation should be correct");

            Assert.AreEqual(new TlvTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x3 }), tag, "Tag Equals function should compare correctly");
        }

        [TestMethod]
        public void TestTlvTagProperties()
        {
            var tag = new TlvTag(0x1, true, true, new byte[] { 0x1, 0x2, 0x3 });
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be preserved");
            Assert.IsTrue(tag.NonCritical, "Tag non critical flag should be preserved");
            Assert.IsTrue(tag.Forward, "Tag forward flag should be preserved");
            CollectionAssert.AreEqual(new byte[] { 0x1, 0x2, 0x3 }, tag.Value, "Tag value should be preserved");
            Assert.AreEqual("TLV[0x1,N,F]:0x010203", tag.ToString(), "Tag string representation should be correct");

            tag.Type = 0x2;
            tag.NonCritical = false;
            tag.Forward = false;
            tag.Value = new byte[] { 0x1, 0x3 };

            Assert.AreEqual((uint)0x2, tag.Type, "Tag type should be set correctly");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be set correctly");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be set correctly");
            CollectionAssert.AreEqual(new byte[] { 0x1, 0x3 }, tag.Value, "Tag value should be set correctly");
            Assert.AreEqual("TLV[0x2]:0x0103", tag.ToString(), "Tag string representation should be correct");
        }

        [TestMethod, ExpectedException(typeof(ArgumentNullException), "Tag should throw null exception when created with null byte array value")]
        public void TestTlvTagCreateFromNullData()
        {
            var tag = new TlvTag(0x1, false, false, null);
        }

        [TestMethod, ExpectedException(typeof(ArgumentNullException), "Tag should throw null exception when created with null tlv tag value")]
        public void TestTlvTagCreateFromNullTag()
        {
            var tag = new TlvTag((TlvTag)null);
        }
    }
}
