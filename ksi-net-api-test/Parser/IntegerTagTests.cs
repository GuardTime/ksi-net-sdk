using System;
using Guardtime.KSI.Utils;
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
        public void TestIntegerTagEquals()
        {
            var tag = new IntegerTag(0x1, false, false, 10);
            Assert.AreEqual(new IntegerTag(0x1, false, false, 10), tag, "Tag Equals function should compare correctly");
            Assert.IsFalse(tag.Equals(new StringTag(0x1, false, false, "test")), "Tag Equals function should compare correctly with other objects");
            Assert.IsFalse(tag.Equals(new object()), "Tag Equals function should compare correctly with other objects");
        }

        [Test]
        public void TestIntegerTagHashCode()
        {
            var tag = new IntegerTag(0x1, false, false, 10);
            Assert.AreEqual(11, tag.GetHashCode(), "Hash code should be correct");
        }

        [Test]
        public void TestIntegerTagToString()
        {
            var tag = new IntegerTag(0x1, false, false, 10);
            Assert.AreEqual("TLV[0x1]:i10", tag.ToString(), "Tag unsigned long representation should be correct");

            tag = new IntegerTag(0x1, true, true, 11);
            Assert.AreEqual("TLV[0x1,N,F]:i11", tag.ToString(), "Tag unsigned long representation should be correct");
        }

        [Test, ExpectedException(typeof(ArgumentException))]
        public void TestTlvTagCreateFromInvalidEncodeTlvTag()
        {
            var tag = new IntegerTag(new InvalidEncodeTlvTag(0x0, false, false));
        }

        [Test, ExpectedException(typeof(ArgumentNullException))]
        public void TestIntegerTagCreateFromNullTag()
        {
            var tag = new IntegerTag((TlvTag)null);
        }

    }
}
