using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Guardtime.KSI.Hashing
{
    [TestClass]
    public class HashAlgorithmTests
    {
        [TestMethod]
        public void TestAlgorithmFromStaticVariable()
        {
            var algorithm = HashAlgorithm.Sha2256;
            Assert.AreEqual(1u, algorithm.Id, "Hash algorithm id should be correct");
            Assert.AreEqual("SHA-256", algorithm.Name, "Hash algorithm name should be correct");
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status, "Hash algorithm status should be correct");
            Assert.AreEqual(32, algorithm.Length, "Hash algorithm length should be correct");
        }

        [TestMethod]
        public void TestAlgorithmGetById()
        {
            var algorithm = HashAlgorithm.GetById(1);
            Assert.AreEqual(1u, algorithm.Id, "Hash algorithm id should be correct");
            Assert.AreEqual("SHA-256", algorithm.Name, "Hash algorithm name should be correct");
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status, "Hash algorithm status should be correct");
            Assert.AreEqual(32, algorithm.Length, "Hash algorithm length should be correct");

            Assert.AreEqual(HashAlgorithm.Sha2256, algorithm);
        }

        [TestMethod]
        public void TestAlgorithmGetByName()
        {
            var algorithm = HashAlgorithm.GetByName("DEFAULT");
            Assert.AreEqual(1u, algorithm.Id, "Hash algorithm id should be correct");
            Assert.AreEqual("SHA-256", algorithm.Name, "Hash algorithm name should be correct");
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status, "Hash algorithm status should be correct");
            Assert.AreEqual(32, algorithm.Length, "Hash algorithm length should be correct");
        }

        [TestMethod]
        public void TestAlgorithmGetByIdWithInvalidId()
        {
            var algorithm = HashAlgorithm.GetById(255);
            Assert.IsNull(algorithm, "Algorithm should not be found with given id");
        }

        [TestMethod]
        public void TestAlgorithmGetByIdWithInvalidName()
        {
            var algorithm = HashAlgorithm.GetByName("TEST");
            Assert.IsNull(algorithm, "Algorithm should not be found with given name");
        }
    }
}
