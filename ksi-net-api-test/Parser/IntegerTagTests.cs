using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Parser
{
    [TestClass]
    public class IntegerTagTest
    {

        [TestMethod]
        public void TestIntegerTagCreateFromTag()
        {
            var rawTag = new RawTag(0x1, false, false, new byte[] {0x1});
            var tag = new IntegerTag(rawTag);
            tag.DecodeValue(rawTag.Value);
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual((ulong)1, tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:i1", tag.ToString(), "Tag string representation should be correct");

            var newTag = new IntegerTag(rawTag);
            newTag.DecodeValue(rawTag.Value);
            Assert.AreEqual(newTag, tag, "Tags should be equal");
        }

        [TestMethod]
        public void TestIntegerTagProperties()
        {
            var rawTag = new RawTag(0x1, true, true, new byte[] {0x1});
            var tag = new IntegerTag(rawTag);
            tag.DecodeValue(rawTag.Value);
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be preserved");
            Assert.IsTrue(tag.NonCritical, "Tag non critical flag should be preserved");
            Assert.IsTrue(tag.Forward, "Tag forward flag should be preserved");
            Assert.AreEqual((ulong)1, tag.Value, "Tag value should be preserved");
            Assert.AreEqual("TLV[0x1,N,F]:i1", tag.ToString(), "Tag string representation should be correct");

            tag.Type = 0x2;
            tag.NonCritical = false;
            tag.Forward = false;
            tag.Value = 5;

            Assert.AreEqual((uint)0x2, tag.Type, "Tag type should be set correctly");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be set correctly");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be set correctly");
            Assert.AreEqual((ulong)5, tag.Value, "Tag value should be set correctly");
            Assert.AreEqual("TLV[0x2]:i5", tag.ToString(), "Tag string representation should be correct");
        }

        [TestMethod, ExpectedException(typeof(ArgumentNullException), "Tag should throw null exception when created with tlv tag null value")]
        public void TestIntegerTagCreateFromNullTag()
        {
            var tag = new IntegerTag(null);
        }
    }
}
