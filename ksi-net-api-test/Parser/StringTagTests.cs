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
using Guardtime.KSI.Parser;
using Guardtime.KSI.Test.Utils;
using NUnit.Framework;

// ReSharper disable ObjectCreationAsStatement

namespace Guardtime.KSI.Test.Parser
{
    [TestFixture]
    public class StringTagTests
    {
        [Test]
        public void TestStringTagCreateFromTag()
        {
            StringTag tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 }));
            Assert.AreEqual(0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual("test message", tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:\"test message\"", tag.ToString(), "Tag string representation should be correct");
        }

        [Test]
        public void TestStringTagEquals()
        {
            StringTag tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 }));
            Assert.AreEqual(new StringTag(tag), tag, "Tags should be equal");
            Assert.IsTrue(tag.Equals(tag), "Tags should be equal");
            Assert.IsTrue(tag == new StringTag(new RawTag(0x1, false, false, new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 })),
                "Tag should compare correctly with other objects");
            Assert.IsTrue(tag != new ChildStringTag(new RawTag(0x1, false, false, new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 })),
                "Tag should compare correctly with other objects");
            Assert.IsFalse(tag.Equals(new RawTag(0x1, false, false, new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 })),
                "Tags should not be equal");
        }

        [Test]
        public void TestStringTagHashCode()
        {
            StringTag tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 }));
            Assert.AreEqual(1246573819, tag.GetHashCode(), "Hash code should be correct");
        }

        [Test]
        public void TestStringTagToString()
        {
            StringTag tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 }));
            Assert.AreEqual("TLV[0x1]:\"test message\"", tag.ToString(), "Tag string representation should be correct");

            tag = new StringTag(new RawTag(0x1, true, true,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 }));
            Assert.AreEqual("TLV[0x1,N,F]:\"test message\"", tag.ToString(), "Tag string representation should be correct");
        }

        [Test]
        public void TestStringTagCastToString()
        {
            StringTag tag = new StringTag(new RawTag(0x1, false, false,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0 }));
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
            RawTag rawTag = new RawTag(0x1, true, true,
                new byte[] { 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65 });

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
            public ChildStringTag(ITlvTag tag) : base(tag)
            {
            }
        }
    }
}