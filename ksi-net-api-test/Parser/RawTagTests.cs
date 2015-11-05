﻿using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;
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
            var tlvTag = new RawTag(0x1, false, false, new byte[] {0x1, 0x2, 0x3});
            var tag = new RawTag(tlvTag);
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new byte[] {0x1, 0x2, 0x3}, tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:0x010203", tag.ToString(), "Tag string representation should be correct");
        }

        [Test]
        public void TestTlvTagEquals()
        {
            var tag = new RawTag(0x1, false, false, new byte[] {0x1, 0x2, 0x3});
            Assert.AreEqual(new RawTag(0x1, false, false, new byte[] {0x1, 0x2, 0x3}), tag, "Tag Equals function should compare correctly");
            Assert.IsTrue(tag.Equals(tag), "Tags should be equal");
            Assert.IsTrue(tag == new RawTag(0x1, false, false, new byte[] {0x1, 0x2, 0x3}), "Tag should compare correctly with other objects");
            Assert.IsTrue(tag != new ChildRawTag(0x1, false, false, new byte[] {0x1, 0x2, 0x3}), "Tag should compare correctly with other objects");
            Assert.IsFalse(tag.Equals(new StringTag(0x1, false, false, "test")), "Tag Equals function should compare correctly with other objects");
            Assert.IsFalse(tag.Equals(new object()), "Tag Equals function should compare correctly with other objects");
        }

        [Test]
        public void TestTlvTagHashCode()
        {
            var tag = new RawTag(0x1, false, false,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0});
            Assert.AreEqual(-10917305, tag.GetHashCode(), "Hash code should be correct");
        }

        [Test]
        public void TestTlvTagToString()
        {
            var tag = new RawTag(0x1, false, false,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0});
            Assert.AreEqual("TLV[0x1]:0x74657374206D65737361676500", tag.ToString(), "Tag byte hex representation should be correct");

            tag = new RawTag(0x1, true, true,
                new byte[] {0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0});
            Assert.AreEqual("TLV[0x1,N,F]:0x74657374206D65737361676500", tag.ToString(), "Tag byte hex representation should be correct");
        }

        [Test]
        public void TestTlvTagCreateFromNullData()
        {
            Assert.Throws<TlvException>(delegate
            {
                new RawTag(0x1, false, false, null);
            });
        }

        [Test]
        public void TestTlvTagCreateFromNullTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                new RawTag((TlvTag)null);
            });
        }

        [Test]
        public void TestTlvTagCreateFromInvalidEncodeTlvTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                new RawTag(new InvalidEncodeTlvTag(0x0, false, false));
            });
        }

        private class ChildRawTag : RawTag
        {
            public ChildRawTag(TlvTag tag) : base(tag)
            {
            }

            public ChildRawTag(uint type, bool nonCritical, bool forward, byte[] value) : base(type, nonCritical, forward, value)
            {
            }
        }
    }
}