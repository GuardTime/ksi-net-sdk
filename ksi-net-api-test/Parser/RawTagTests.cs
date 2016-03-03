/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;
using NUnit.Framework;

// ReSharper disable ObjectCreationAsStatement

namespace Guardtime.KSI.Parser
{
    [TestFixture]
    public class RawTagTests
    {
        [Test]
        public void TestTlvTagCreateFromData()
        {
            RawTag tag = new RawTag(0x1, true, true, new byte[] { 0x1, 0x2, 0x3 });
            Assert.AreEqual(0x1, tag.Type, "Tag type should be preserved");
            Assert.IsTrue(tag.NonCritical, "Tag non critical flag should be preserved");
            Assert.IsTrue(tag.Forward, "Tag forward flag should be preserved");
            CollectionAssert.AreEqual(new byte[] { 0x1, 0x2, 0x3 }, tag.Value, "Tag value should be preserved");
            Assert.AreEqual("TLV[0x1,N,F]:0x010203", tag.ToString());
        }

        [Test]
        public void TestTlvTagCreateFromTag()
        {
            RawTag tlvTag = new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x3 });
            RawTag tag = new RawTag(tlvTag);
            Assert.AreEqual(0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new byte[] { 0x1, 0x2, 0x3 }, tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:0x010203", tag.ToString(), "Tag string representation should be correct");
        }

        [Test]
        public void TestTlvTagEquals()
        {
            RawTag tag = new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x3 });
            Assert.AreEqual(new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x3 }), tag, "Tag Equals function should compare correctly");
            Assert.IsTrue(tag.Equals(tag), "Tags should be equal");
            Assert.IsTrue(tag == new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x3 }), "Tag should compare correctly with other objects");
            Assert.IsTrue(tag != new ChildRawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x3 }), "Tag should compare correctly with other objects");
            Assert.IsFalse(tag.Equals(new StringTag(0x1, false, false, "test")), "Tag Equals function should compare correctly with other objects");
            Assert.IsFalse(tag.Equals(new object()), "Tag Equals function should compare correctly with other objects");
        }

        [Test]
        public void TestTlvTagHashCode()
        {
            RawTag tag = new RawTag(0x1, false, false,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 });
            Assert.AreEqual(-10917305, tag.GetHashCode(), "Hash code should be correct");
        }

        [Test]
        public void TestTlvTagToString()
        {
            RawTag tag = new RawTag(0x1, false, false,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 });
            Assert.AreEqual("TLV[0x1]:0x74657374206D65737361676500", tag.ToString(), "Tag byte hex representation should be correct");

            tag = new RawTag(0x1, true, true,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 });
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
                new RawTag(null);
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
            public ChildRawTag(uint type, bool nonCritical, bool forward, byte[] value) : base(type, nonCritical, forward, value)
            {
            }
        }
    }
}