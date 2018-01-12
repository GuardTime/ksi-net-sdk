/*
 * Copyright 2013-2017 Guardtime, Inc.
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

using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Test.Utils;
using NUnit.Framework;

// ReSharper disable ObjectCreationAsStatement

namespace Guardtime.KSI.Test.Parser
{
    [TestFixture]
    public class IntegerTagTest
    {
        [Test]
        public void TestIntegerTagCreateFromTag()
        {
            RawTag rawTag = new RawTag(0x1, false, false, new byte[] { 0x1 });
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
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new IntegerTag(null);
            });
            Assert.AreEqual("tag", ex.ParamName);
        }

        private class ChildIntegerTag : IntegerTag
        {
            public ChildIntegerTag(uint type, bool nonCritical, bool forward, ulong value) : base(type, nonCritical, forward, value)
            {
            }
        }
    }
}