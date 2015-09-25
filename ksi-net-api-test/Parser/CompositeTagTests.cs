using System;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using NUnit.Framework;

namespace Guardtime.KSI.Parser
{
    [TestFixture]
    public class CompositeTagTests
    {
        [Test]
        public void TestCompositeTagCreateFromTlvTag()
        {
            var tag = new CompositeTestTag(new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x1, 0x2, 0x2, 0x2, 0x3, 0x4 }));

            Assert.AreEqual(0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new List<TlvTag> { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }, tag, "Tag value should be decoded correctly");
        }

        [Test]
        public void TestCompositeTagCreateFromData()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() {new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 })});

            Assert.AreEqual(0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new List<TlvTag> { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }, tag, "Tag value should be decoded correctly");
        }

        [Test]
        public void TestCompositeTagSettingAndGettingValue()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new CompositeTestTag(0x5, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }) });
            CollectionAssert.AreEqual(new List<TlvTag> { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }, tag.CompositeTestTagValue, "Tag child value should be decoded correctly");
            CollectionAssert.AreEqual(new byte[] { 0x5, 0x8, 0x1, 0x2, 0x1, 0x2, 0x2, 0x2, 0x3, 0x4 }, tag.EncodeValue(), "Tag value should be encoded correctly");

            tag.SetCompositeTestTagValue(new CompositeTestTag(0x5, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1 }) }));
            CollectionAssert.AreEqual(new List<TlvTag> { new RawTag(0x1, false, false, new byte[] { 0x1 }) }, tag.CompositeTestTagValue, "Tag child value should be decoded correctly");
            CollectionAssert.AreEqual(new byte[] { 0x5, 0x3, 0x1, 0x1, 0x1 }, tag.EncodeValue(), "Tag value should be encoded correctly");

            tag.SetCompositeTestTagValue(new CompositeTestTag(0x5, false, false, new List<TlvTag>() { new RawTag(0x2, false, false, new byte[] { 0x0 }) }));
            CollectionAssert.AreEqual(new List<TlvTag> { new RawTag(0x2, false, false, new byte[] { 0x0 }) }, tag.CompositeTestTagValue, "Tag child value should be decoded correctly");
            CollectionAssert.AreEqual(new byte[] { 0x5, 0x3, 0x2, 0x1, 0x0 }, tag.EncodeValue(), "Tag value should be encoded correctly");
        }

        [Test]
        public void TestEncodeValue()
        {
            var tag = new CompositeTestTag(new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x1, 0x2, 0x2, 0x2, 0x3, 0x4 }));
            CollectionAssert.AreEqual(new byte[] { 0x1, 0x2, 0x1, 0x2, 0x2, 0x2, 0x3, 0x4 }, tag.EncodeValue(), "Tag should encode value correctly");
        }

        [Test]
        public void TestHashCode()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] {0x1, 0x2}), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) });
            Assert.AreEqual(32867, tag.GetHashCode(), "Tag hash code should be correct");
        }

        [Test]
        public void TestEquals()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) });
            Assert.AreEqual(new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }), tag, "Tags should be equal");
            Assert.IsTrue(tag == new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }), "Tags should be equal");
            Assert.IsTrue(tag != new ChildCompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }), "Tags should be equal");
            Assert.IsFalse(new CompositeTestTag(0x2, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }) == tag, "Tags should not be equal");
            Assert.IsFalse(tag.Equals(new RawTag(0x1, false, false, new byte[] { })), "Tags should not be equal");
        }

        [Test]
        public void TestToString()
        {
            var tag = new CompositeTestTag(0x1, true, true, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }), new CompositeTestTag(0x5, false, false, new List<TlvTag>() {new RawTag(0x1, false, false, new byte[]{})}) });
            Assert.AreEqual("TLV[0x1,N,F]:\n  TLV[0x1]:0x0102\n  TLV[0x2]:0x0304\n  TLV[0x5]:\n    TLV[0x1]:0x", tag.ToString(), "Tag string representation should be correct");
        }

        [Test]
        public void TestIsValidStructure()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }), new CompositeTestTag(0x5, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { }) }) });
        }

        [Test]
        public void TestPutNullTagToCompositeTagList()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) });
            Assert.Throws<ArgumentNullException>(delegate { tag.SetCompositeTestTagValue(null);  });
        }

        [Test]
        public void TestCompositeTagAddNullValueToSpecificPosition()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }) });
            Assert.Throws<ArgumentNullException>(delegate { tag.SetTagToFirstPosition(null); });
        }

        [Test]
        public void TestTryReplaceTagNotInCompositeTagList()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }), new RawTag(0x1, false, false, new byte[] { 0x4 }) });
            Assert.IsNull(tag.ReplaceTagImpl(tag, new RawTag(0x5, false, false, new byte[] { })));
        }

        [Test]
        public void TestAddNullTagToCompositeTagList()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) });
            Assert.Throws<ArgumentNullException>(delegate { tag.AddTagImpl(null); });
        }

        [Test]
        public void TestCompositeTagCreateFromDataNullValue()
        {
            Assert.Throws<ArgumentNullException>(delegate
            {
                new CompositeTestTag(0x1, false, false, null);
            });
        }

        [Test]
        public void TestIsInvalidStructure()
        {
            Assert.Throws<InvalidTlvStructureException>(delegate
            {
                new CompositeTestTag(0x1, false, false,
                    new List<TlvTag>()
                    {
                        new RawTag(0x1, false, false, new byte[] {0x1, 0x2}),
                        new RawTag(0x3, false, false, new byte[] {0x3, 0x4})
                    });
            }, "Invalid tag");
        }

        [Test]
        public void TestVerifyCriticalFlag()
        {
            var tag = new CompositeTestTag(0x1, false, false, new List<TlvTag>() { new RawTag(0x25, true, false, new byte[] { 0x1, 0x2 }), new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }), new CompositeTestTag(0x5, false, false, new List<TlvTag>() { new RawTag(0x1, false, false, new byte[] { }) }) });
            Assert.Throws<ArgumentNullException>(delegate
            {
                tag.VerifyCriticalFlagWithoutTag();
            });
            
        }

        private class CompositeTestTag : CompositeTag
        {
            public CompositeTestTag CompositeTestTagValue { get; private set; }

            public CompositeTestTag(TlvTag tag) : base(tag)
            {
                BuildStructure();
            }

            public CompositeTestTag(uint type, bool nonCritical, bool forward, List<TlvTag> value)
            : base(type, nonCritical, forward, value)
            {
                BuildStructure();
            }

            private void BuildStructure()
            {
                for (var i = 0; i < Count; i++)
                {
                    switch (this[i].Type)
                    {
                        case 0x5:
                            CompositeTestTagValue = new CompositeTestTag(this[i]);
                            this[i] = CompositeTestTagValue;
                            break;
                        case 0x2:
                        case 0x1:
                            break;
                        default:
                            VerifyCriticalFlag(this[i]);
                            break;
                    }
                }
            }

            public void SetCompositeTestTagValue(CompositeTestTag tag)
            {
                PutTag(tag, CompositeTestTagValue);
                CompositeTestTagValue = tag;
            }

            public TlvTag AddTagImpl(TlvTag tag)
            {
                return AddTag(tag);
            }

            public TlvTag ReplaceTagImpl(TlvTag tag, TlvTag previousTag)
            {
                return ReplaceTag(tag, previousTag);
            }

            public void SetTagToFirstPosition(TlvTag tag)
            {
                this[0] = tag;
            }

            public void VerifyCriticalFlagWithoutTag()
            {
                VerifyCriticalFlag(null);
            }
        }

        private class ChildCompositeTestTag : CompositeTestTag
        {
            public ChildCompositeTestTag(TlvTag tag) : base(tag)
            {
            }

            public ChildCompositeTestTag(uint type, bool nonCritical, bool forward, List<TlvTag> value) : base(type, nonCritical, forward, value)
            {
            }
        }
    }
}