using System;
using NUnit.Framework;

namespace Guardtime.KSI.Parser
{
    [TestFixture]
    public class IntegerTagTest
    {

        [Test]
        public void TestIntegerTagCreateFromTag()
        {
            var rawTag = new RawTag(0x1, false, false, new byte[] {0x1});
            var tag = new IntegerTag(rawTag);
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual((ulong)1, tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:i1", tag.ToString(), "Tag string representation should be correct");

            var newTag = new IntegerTag(rawTag);
            Assert.AreEqual(newTag, tag, "Value should be equal");
        }

        [Test]
        public void TestIntegerTagCreateFromBytes()
        {
            var tag = new IntegerTag(new byte[] {0x1, 0x1, 0x1});
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual((ulong)1, tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:i1", tag.ToString(), "Tag string representation should be correct");

            var newTag = new IntegerTag(tag);
            Assert.AreEqual(newTag, tag, "Value should be equal");
        }

        [Test, ExpectedException(typeof(ArgumentNullException))]
        public void TestIntegerTagCreateFromNullTag()
        {
            var tag = new IntegerTag((TlvTag)null);
        }
    }
}
