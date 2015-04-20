using System;
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
            Assert.AreEqual(1u, algorithm.Id);
            Assert.AreEqual("SHA-256", algorithm.Name);
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status);
            Assert.AreEqual(32, algorithm.Length);
        }

        [TestMethod]
        public void TestAlgorithmGetById()
        {
            var algorithm = HashAlgorithm.GetById(1);
            Assert.AreEqual(1u, algorithm.Id);
            Assert.AreEqual("SHA-256", algorithm.Name);
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status);
            Assert.AreEqual(32, algorithm.Length);

            Assert.AreEqual(HashAlgorithm.Sha2256, algorithm);
        }

        [TestMethod]
        public void TestAlgorithmGetByName()
        {
            var algorithm = HashAlgorithm.GetByName("DEFAULT");
            Assert.AreEqual(1u, algorithm.Id);
            Assert.AreEqual("SHA-256", algorithm.Name);
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status);
            Assert.AreEqual(32, algorithm.Length);
        }

        [TestMethod]
        public void TestAlgorithmGetByIdWithInvalidId()
        {
            var algorithm = HashAlgorithm.GetById(255);
            Assert.IsNull(algorithm);
        }

        [TestMethod]
        public void TestAlgorithmGetByIdWithInvalidName()
        {
            var algorithm = HashAlgorithm.GetByName("TEST");
            Assert.IsNull(algorithm);
        }
    }
}
