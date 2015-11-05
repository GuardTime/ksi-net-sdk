using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Parser
{
    [TestFixture]
    public class StringTagTests
    {
        [Test]
        public void TestStringTagCreateFromTag()
        {
            var tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0}));
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual("test message", tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:\"test message\"", tag.ToString(), "Tag string representation should be correct");
        }

        [Test]
        public void TestStringTagEquals()
        {
            var tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0}));
            Assert.AreEqual(new StringTag(tag), tag, "Tags should be equal");
            Assert.IsTrue(tag.Equals(tag), "Tags should be equal");
            Assert.IsTrue(tag == new StringTag(new RawTag(0x1, false, false, new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0})),
                "Tag should compare correctly with other objects");
            Assert.IsTrue(tag != new ChildStringTag(new RawTag(0x1, false, false, new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0})),
                "Tag should compare correctly with other objects");
            Assert.IsFalse(tag.Equals(new RawTag(0x1, false, false, new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0})),
                "Tags should not be equal");
        }

        [Test]
        public void TestStringTagHashCode()
        {
            var tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0}));
            Assert.AreEqual(1246573819, tag.GetHashCode(), "Hash code should be correct");
        }

        [Test]
        public void TestStringTagToString()
        {
            var tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0}));
            Assert.AreEqual("TLV[0x1]:\"test message\"", tag.ToString(), "Tag string representation should be correct");

            tag = new StringTag(new RawTag(0x1, true, true,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0}));
            Assert.AreEqual("TLV[0x1,N,F]:\"test message\"", tag.ToString(), "Tag string representation should be correct");
        }

        [Test]
        public void TestStringTagCastToString()
        {
            var tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0}));
            Assert.AreEqual("test message", tag.Value, "Tag should cast correctly to string");
        }

        [Test]
        public void TestTlvTagCreateFromInvalidEncodeTlvTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                new StringTag(new InvalidEncodeTlvTag(0x0, false, false));
            });
        }

        [Test]
        public void TestStringTagDecodeNotEndingWithNullByte()
        {
            var rawTag = new RawTag(0x1, true, true,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65});

            Assert.Throws<KsiException>(delegate
            {
                new StringTag(rawTag);
            }, "String must be null terminated");
        }

        [Test]
        public void TestStringTagCreateFromNullTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                new StringTag(null);
            });
        }

        [Test]
        public void TestStringTagCreateWithNullValue()
        {
            Assert.Throws<TlvException>(delegate
            {
                new StringTag(0x1, true, true, null);
            });
        }

        private class ChildStringTag : StringTag
        {
            public ChildStringTag(TlvTag tag) : base(tag)
            {
            }

            public ChildStringTag(uint type, bool nonCritical, bool forward, string value) : base(type, nonCritical, forward, value)
            {
            }
        }
    }
}