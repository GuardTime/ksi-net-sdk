using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;
using NUnit.Framework;

// ReSharper disable ObjectCreationAsStatement

namespace Guardtime.KSI.Parser
{
    [TestFixture]
    public class IntegerTagTest
    {
        [Test]
        public void TestIntegerTagCreateFromTag()
        {
            RawTag rawTag = new RawTag(0x1, false, false, new byte[] {0x1});
            IntegerTag tag = new IntegerTag(rawTag);
            Assert.AreEqual(0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual(1, tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:i1", tag.ToString(), "Tag string representation should be correct");

            IntegerTag newTag = new IntegerTag(rawTag);
            Assert.AreEqual(newTag, tag, "Value should be equal");
        }

        [Test]
        public void TestIntegerTagEquals()
        {
            IntegerTag tag = new IntegerTag(0x1, false, false, 10);
            Assert.AreEqual(new IntegerTag(0x1, false, false, 10), tag, "Tag Equals function should compare correctly");
            Assert.IsTrue(tag.Equals(tag), "Tags should be equal");
            Assert.IsTrue(tag == new IntegerTag(0x1, false, false, 10), "Tag should compare correctly with other objects");
            Assert.IsTrue(tag != new ChildIntegerTag(0x1, false, false, 10), "Tag should compare correctly with other objects");
            Assert.IsFalse(tag.Equals(new StringTag(0x1, false, false, "test")), "Tag Equals function should compare correctly with other objects");
            Assert.IsFalse(tag.Equals(new object()), "Tag Equals function should compare correctly with other objects");
        }

        [Test]
        public void TestIntegerTagHashCode()
        {
            IntegerTag tag = new IntegerTag(0x1, false, false, 10);
            Assert.AreEqual(11, tag.GetHashCode(), "Hash code should be correct");
        }

        [Test]
        public void TestIntegerTagToString()
        {
            IntegerTag tag = new IntegerTag(0x1, false, false, 10);
            Assert.AreEqual("TLV[0x1]:i10", tag.ToString(), "Tag unsigned long representation should be correct");

            tag = new IntegerTag(0x1, true, true, 11);
            Assert.AreEqual("TLV[0x1,N,F]:i11", tag.ToString(), "Tag unsigned long representation should be correct");
        }

        [Test]
        public void TestTlvTagCreateFromInvalidEncodeTlvTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                new IntegerTag(new InvalidEncodeTlvTag(0x0, false, false));
            });
        }

        [Test]
        public void TestIntegerTagCreateFromNullTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                new IntegerTag(null);
            });
        }

        private class ChildIntegerTag : IntegerTag
        {
            public ChildIntegerTag(uint type, bool nonCritical, bool forward, ulong value) : base(type, nonCritical, forward, value)
            {
            }
        }
    }
}