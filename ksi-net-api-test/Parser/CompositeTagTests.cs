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

using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using NUnit.Framework;

// ReSharper disable ObjectCreationAsStatement

namespace Guardtime.KSI.Test.Parser
{
    [TestFixture]
    public class CompositeTagTests
    {
        [Test]
        public void TestCompositeTagCreateFromTlvTag()
        {
            CompositeTestTag tag = new CompositeTestTag(new RawTag(0x1, true, false, new byte[] { 0x41, 0x2, 0x1, 0x2, 0x42, 0x2, 0x3, 0x4 }));

            Assert.AreEqual(0x1, tag.Type, "Tag type should be correct");
            Assert.True(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) }, tag,
                "Tag value should be decoded correctly");
        }

        [Test]
        public void TestCompositeTagCreateFromData()
        {
            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) });

            Assert.AreEqual(0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) }, tag,
                "Tag value should be decoded correctly");
        }

        [Test]
        public void TestCompositeTagSettingAndGettingValue()
        {
            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(0x5, true, false,
                        new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) })
                });
            CollectionAssert.AreEqual(new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) },
                tag.CompositeTestTagValue, "1. Tag child value should be decoded correctly");
            CollectionAssert.AreEqual(new byte[] { 0x45, 0x8, 0x41, 0x2, 0x1, 0x2, 0x42, 0x2, 0x3, 0x4 }, tag.EncodeValue(), "2. Tag value should be encoded correctly");
        }

        [Test]
        public void TestEncodeValue()
        {
            CompositeTestTag tag = new CompositeTestTag(new RawTag(0x1, true, false, new byte[] { 0x41, 0x2, 0x1, 0x2, 0x42, 0x2, 0x3, 0x4 }));
            CollectionAssert.AreEqual(new byte[] { 0x41, 0x2, 0x1, 0x2, 0x42, 0x2, 0x3, 0x4 }, tag.EncodeValue(), "Tag should encode value correctly");
        }

        [Test]
        public void TestHashCode()
        {
            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) });
            Assert.AreEqual(32899, tag.GetHashCode(), "Tag hash code should be correct");
        }

        [Test]
        public void TestEquals()
        {
            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) });
            Assert.AreEqual(
                new CompositeTestTag(0x1, false, false,
                    new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) }), tag, "1. Tags should be equal");
            Assert.IsTrue(
                tag ==
                new CompositeTestTag(0x1, false, false,
                    new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) }), "2. Tags should be equal");
            Assert.IsTrue(
                tag !=
                new ChildCompositeTestTag(0x1, false, false,
                    new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) }), "3. Tags should be equal");
            Assert.IsFalse(
                new CompositeTestTag(0x2, false, false,
                    new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }) }) == tag,
                "4. Tags should not be equal");
            Assert.IsFalse(tag.Equals(new RawTag(0x1, true, false, new byte[] { })), "5. Tags should not be equal");
        }

        [Test]
        public void TestToString()
        {
            CompositeTestTag tag = new CompositeTestTag(0x1, true, true,
                new ITlvTag[]
                {
                    new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }),
                    new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }),
                    new CompositeTestTag(0x5, true, false, new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { 8, 9 }) })
                });

            string expected = "TLV[0x1,N,F]:" + Environment.NewLine + "  TLV[0x1,N]:0x0102" + Environment.NewLine + "  TLV[0x2,N]:0x0304" + Environment.NewLine + "  TLV[0x5,N]:" +
                              Environment.NewLine +
                              "    TLV[0x1,N]:0x0809";
            Assert.AreEqual(expected, tag.ToString(), "1. Tag string representation should be correct");

            tag = new CompositeTestTag(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(expected, tag.ToString(), "2. Tag string representation should be correct");
        }

        [Test]
        public void TestIsValidStructure()
        {
            new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }),
                    new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }),
                    new CompositeTestTag(0x5, true, false, new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { }) })
                });
        }

        [Test]
        public void TestCompositeTagAddNullValueToSpecificPosition()
        {
            Assert.Throws<TlvException>(delegate
            {
                new CompositeTestTag(0x1, false, false, new ITlvTag[] { null });
            });
        }

        [Test]
        public void TestCompositeTagCreateFromDataNullValue()
        {
            Assert.Throws<TlvException>(delegate
            {
                new CompositeTestTag(0x1, false, false, null);
            });
        }

        [Test]
        public void TestIsInvalidStructure()
        {
            Assert.Throws<TlvException>(delegate
            {
                new CompositeTestTag(0x1, false, false,
                    new ITlvTag[]
                    {
                        new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }),
                        new RawTag(0x3, false, false, new byte[] { 0x3, 0x4 })
                    });
            });
        }

        [Test]
        public void TestVerifyCriticalFlag()
        {
            CompositeTestTag tag = new CompositeTestTag(0x1, false, false,
                new ITlvTag[]
                {
                    new RawTag(0x25, true, false, new byte[] { 0x1, 0x2 }),
                    new RawTag(0x1, true, false, new byte[] { 0x1, 0x2 }),
                    new RawTag(0x2, true, false, new byte[] { 0x3, 0x4 }),
                    new CompositeTestTag(0x5, true, false, new ITlvTag[] { new RawTag(0x1, true, false, new byte[] { }) })
                });
            Assert.Throws<TlvException>(delegate
            {
                tag.VerifyCriticalFlagWithoutTag();
            });
        }

        private class CompositeTestTag : CompositeTag
        {
            public CompositeTestTag CompositeTestTagValue { get; private set; }

            public CompositeTestTag(ITlvTag tag) : base(tag)
            {
                BuildStructure();
            }

            public CompositeTestTag(uint type, bool nonCritical, bool forward, ITlvTag[] childTags)
                : base(type, nonCritical, forward, childTags)
            {
                BuildStructure();
            }

            private void BuildStructure()
            {
                for (int i = 0; i < Count; i++)
                {
                    ITlvTag childTag = this[i];

                    switch (childTag.Type)
                    {
                        case 0x5:
                            this[i] = CompositeTestTagValue = childTag as CompositeTestTag ?? new CompositeTestTag(childTag);
                            break;
                        case 0x2:
                        case 0x1:
                            break;
                        default:
                            VerifyUnknownTag(childTag);
                            break;
                    }
                }
            }

            public void VerifyCriticalFlagWithoutTag()
            {
                VerifyUnknownTag(null);
            }
        }

        private class ChildCompositeTestTag : CompositeTestTag
        {
            public ChildCompositeTestTag(uint type, bool nonCritical, bool forward, ITlvTag[] childTags) : base(type, nonCritical, forward, childTags)
            {
            }
        }
    }
}