using System.Collections.Generic;
using NUnit.Framework;

namespace Guardtime.KSI.Parser
{
    [TestFixture]
    public class CompositeTagTests
    {
        [Test]
        public void TestCompositeTagCreateFromBytes()
        {
            var tag = new CompositeTestTag(new byte[] { 0x1, 0x8, 0x1, 0x2, 0x1, 0x2, 0x2, 0x2, 0x3, 0x4 });

            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new List<TlvTag> { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }, tag.Value, "Tag value should be decoded correctly");
        }

        [Test]
        public void TestCompositeTagCreateFromTlvTag()
        {
            var tag = new CompositeTestTag(new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x1, 0x2, 0x2, 0x2, 0x3, 0x4 }));

            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            CollectionAssert.AreEqual(new List<TlvTag> { new RawTag(0x1, false, false, new byte[] { 0x1, 0x2 }), new RawTag(0x2, false, false, new byte[] { 0x3, 0x4 }) }, tag.Value, "Tag value should be decoded correctly");
        }

        [Test]
        public void TestEncodeValue()
        {
            var tag = new CompositeTestTag(new RawTag(0x1, false, false, new byte[] { 0x1, 0x2, 0x1, 0x2, 0x2, 0x2, 0x3, 0x4 }));
            CollectionAssert.AreEqual(new byte[] { 0x1, 0x2, 0x1, 0x2, 0x2, 0x2, 0x3, 0x4 }, tag.EncodeValue(), "Tag should encode value correctly");
        }

        [Test]
        public void ToStringTest()
        {
            var tag = new CompositeTestTag(new byte[] { 0x1, 0x8, 0x1, 0x2, 0x1, 0x2, 0x2, 0x2, 0x3, 0x4 });
            Assert.AreEqual("TLV[0x1]:\n  TLV[0x1]:0x0102\n  TLV[0x2]:0x0304", tag.ToString(), "Tag string representation should be correct");
        }

        // TODO: Make some more tests
        class CompositeTestTag : CompositeTag
        {
            public CompositeTestTag(byte[] bytes) : base(bytes)
            {
            }

            public CompositeTestTag(TlvTag tag) : base(tag)
            {
            }

            public override bool IsValidStructure()
            {
                throw new System.NotImplementedException();
            }
        }

        [Test()]
        public void TestReplaceTag()
        {
//            Assert.Fail();
        }

        [Test()]
        public void TestAddTag()
        {
//            Assert.Fail();
        }

        [Test()]
        public void TestPutTag()
        {
//            Assert.Fail();
        }
    }
}