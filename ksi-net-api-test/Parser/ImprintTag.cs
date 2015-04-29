using System;
using Guardtime.KSI.Hashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Parser
{
    [TestClass]
    public class ImprintTagTest
    {

        [TestMethod]
        public void TestImprintTagCreateFromTag()
        {
            var tag = new ImprintTag(new RawTag(0x1, false, false, new byte[] { 0x1, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32 }));
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be correct");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be correct");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be correct");
            Assert.AreEqual(new DataHash(HashAlgorithm.Sha2256, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32 }), tag.Value, "Tag value should be decoded correctly");
            Assert.AreEqual("TLV[0x1]:0x010102030405060708091011121314151617181920212223242526272829303132", tag.ToString(), "Tag string representation should be correct");
        }

        [TestMethod]
        public void TestImprintTagProperties()
        {
            var tag = new ImprintTag(new RawTag(0x1, true, true, new byte[] { 0x1, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32 }));
            Assert.AreEqual((uint)0x1, tag.Type, "Tag type should be preserved");
            Assert.IsTrue(tag.NonCritical, "Tag non critical flag should be preserved");
            Assert.IsTrue(tag.Forward, "Tag forward flag should be preserved");
            Assert.AreEqual(new DataHash(HashAlgorithm.Sha2256, new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32 }), tag.Value, "Tag value should be preserved");
            Assert.AreEqual("TLV[0x1,N,F]:0x010102030405060708091011121314151617181920212223242526272829303132", tag.ToString(), "Tag string representation should be correct");

            tag.Type = 0x2;
            tag.NonCritical = false;
            tag.Forward = false;
            tag.Value = new DataHash(HashAlgorithm.Sha2224, new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28 });

            Assert.AreEqual((uint)0x2, tag.Type, "Tag type should be set correctly");
            Assert.IsFalse(tag.NonCritical, "Tag non critical flag should be set correctly");
            Assert.IsFalse(tag.Forward, "Tag forward flag should be set correctly");
            Assert.AreEqual(new DataHash(HashAlgorithm.Sha2224, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28 }), tag.Value, "Tag value should be set correctly");
            Assert.AreEqual("TLV[0x2]:0x030102030405060708090A0B0C0D0E0F101112131415161718191A1B1C", tag.ToString(), "Tag string representation should be correct");
        }

        [TestMethod, ExpectedException(typeof(ArgumentNullException), "Tag should throw null exception when created with tlv tag null value")]
        public void TestImprintTagCreateFromNullTag()
        {
            var tag = new ImprintTag(null);
        }

    }
}
