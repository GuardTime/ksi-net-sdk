using System;
using NUnit.Framework;

namespace Guardtime.KSI.Parser
{
    [TestFixture]
    public class StringTagTests
    {

        [Test]
        public void TestStringTagCreateFromTag()
        {
            var rawTag = new RawTag(0x1, false, false,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 });
            var tag = new StringTag(rawTag);
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual("test message", tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:\"test message\"", tag.ToString(), "Tag string representation should be correct");

            var newTag = new StringTag(rawTag);
            Assert.AreEqual(newTag, tag, "Value should be equal");
        }

        [Test]
        public void TestStringTagCreateFromBytes()
        {
            var tag = new StringTag(new byte[] { 0x1, 0xd, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 });
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual("test message", tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:\"test message\"", tag.ToString(), "Tag string representation should be correct");

            var newTag = new StringTag(tag);
            Assert.AreEqual(newTag, tag, "Value should be equal");
        }

        [Test, ExpectedException(typeof(FormatException))]
        public void TestStringTagDecodeNotEndingWithNullByte()
        {
            var rawTag = new RawTag(0x1, true, true,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65 });
            var tag = new StringTag(rawTag);
        }

        [Test, ExpectedException(typeof(ArgumentNullException))]
        public void TestStringTagCreateFromNullTag()
        {
            var tag = new StringTag((TlvTag)null);
        }
    }
}
