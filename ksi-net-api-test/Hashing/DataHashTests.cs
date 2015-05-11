using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Hashing
{
    [TestClass]
    public class DataHashTests
    {
        [TestMethod]
        public void TestDataHashFromAlgorithmAndValue()
        {
            var dataHash = new DataHash(HashAlgorithm.Sha2256, new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32});
            Assert.AreEqual(HashAlgorithm.Sha2256, dataHash.Algorithm, "Algorithm should be preserved");
            CollectionAssert.AreEqual(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }, dataHash.Imprint, "Hash imprint should be created correctly");
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }, dataHash.Value, "Hash value should be preserved");
            Assert.AreEqual("SHA-256:[0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20]", dataHash.ToString(), "Hash string representation should be in correct format");
        }

        [TestMethod]
        public void TestDataHashFromImprint()
        {
            var dataHash = new DataHash(new byte[] {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });
            Assert.AreEqual(HashAlgorithm.Sha2256, dataHash.Algorithm, "Algorithm should be preserved");
            CollectionAssert.AreEqual(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }, dataHash.Imprint, "Hash imprint should be created correctly");
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }, dataHash.Value, "Hash value should be preserved");
            Assert.AreEqual("SHA-256:[0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20]", dataHash.ToString(), "Hash string representation should be in correct format");
        }

        [TestMethod]
        public void TestDataHashEquals()
        {
            var dataHash = new DataHash(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });
            Assert.IsTrue(dataHash.Equals(new DataHash(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })), "Hash should be equal to itself");
            Assert.IsFalse(dataHash.Equals(null), "Hash should not equal to null");
            Assert.IsFalse(dataHash.Equals(0), "Hash should not equal to 0");
            Assert.IsFalse(dataHash.Equals("test"), "Hash should not equal to string");
            Assert.AreEqual(new DataHash(HashAlgorithm.Sha2256, new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}), dataHash, "Hash should be equal to similar hash algorithm and value");
            Assert.AreEqual("SHA-256:[0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20]", dataHash.ToString(), "Hash string representation should be in correct format");
        }


    }
}
