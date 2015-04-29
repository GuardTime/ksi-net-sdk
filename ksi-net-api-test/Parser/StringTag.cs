using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Parser
{
    [TestClass]
    public class StringTagTest
    {

        [TestMethod]
        public void TestStringTagCreateFromTag()
        {
            var tag = new StringTag(new RawTag(0x1, false, false, new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 }));
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual("test message", tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:\"test message\"", tag.ToString(), "Tag string representation should be correct");
        }

        [TestMethod]
        public void TestStringTagProperties()
        {
            var tag = new StringTag(new RawTag(0x1, true, true, new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 }));
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be preserved");
            Assert.IsTrue(tag.NonCritical, "Tag non critical flag should be preserved");
            Assert.IsTrue(tag.Forward, "Tag forward flag should be preserved");
            Assert.AreEqual("test message", tag.Value, "Tag value should be preserved");
            Assert.AreEqual("TLV[0x1,N,F]:\"test message\"", tag.ToString(), "Tag string representation should be correct");

            tag.Type = 0x2;
            tag.NonCritical = false;
            tag.Forward = false;
            tag.Value = "test";

            Assert.AreEqual((uint)0x2, tag.Type, "Tag type should be set correctly");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be set correctly");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be set correctly");
            Assert.AreEqual("test", tag.Value, "Tag value should be set correctly");
            Assert.AreEqual("TLV[0x2]:\"test\"", tag.ToString(), "Tag string representation should be correct");
        }

        [TestMethod, ExpectedException(typeof(ArgumentNullException), "Tag should throw null exception when created with tlv tag null value")]
        public void TestStringTagCreateFromNullTag()
        {
            var tag = new StringTag(null);
        }
    }
}
