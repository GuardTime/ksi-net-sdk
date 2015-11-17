using System.Collections.Generic;
using NUnit.Framework;

namespace Guardtime.KSI.Hashing
{
    [TestFixture]
    public class HashAlgorithmTests
    {
        [Test]
        public void TestAlgorithmFromStaticVariable()
        {
            HashAlgorithm algorithm = HashAlgorithm.Sha2256;
            Assert.AreEqual(1u, algorithm.Id, "Hash algorithm id should be correct");
            Assert.AreEqual("SHA-256", algorithm.Name, "Hash algorithm name should be correct");
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status, "Hash algorithm status should be correct");
            Assert.AreEqual(32, algorithm.Length, "Hash algorithm length should be correct");
        }

        [Test]
        public void TestAlgorithmGetById()
        {
            HashAlgorithm algorithm = HashAlgorithm.GetById(1);
            Assert.AreEqual(1u, algorithm.Id, "Hash algorithm id should be correct");
            Assert.AreEqual("SHA-256", algorithm.Name, "Hash algorithm name should be correct");
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status, "Hash algorithm status should be correct");
            Assert.AreEqual(32, algorithm.Length, "Hash algorithm length should be correct");

            Assert.AreEqual(HashAlgorithm.Sha2256, algorithm);
        }

        [Test]
        public void TestAlgorithmGetByName()
        {
            HashAlgorithm algorithm = HashAlgorithm.GetByName("DEFAULT");
            Assert.AreEqual(1u, algorithm.Id, "Hash algorithm id should be correct");
            Assert.AreEqual("SHA-256", algorithm.Name, "Hash algorithm name should be correct");
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status, "Hash algorithm status should be correct");
            Assert.AreEqual(32, algorithm.Length, "Hash algorithm length should be correct");
        }

        [Test]
        public void TestGetNamesList()
        {
            List<string> names = HashAlgorithm.GetNamesList();
            Assert.AreEqual(11, names.Count);
        }

        [Test]
        public void TestAlgorithmGetByIdWithInvalidId()
        {
            HashAlgorithm algorithm = HashAlgorithm.GetById(255);
            Assert.IsNull(algorithm, "Algorithm should not be found with given id");
        }

        [Test]
        public void TestAlgorithmGetByIdWithInvalidName()
        {
            HashAlgorithm algorithm = HashAlgorithm.GetByName("TEST");
            Assert.IsNull(algorithm, "Algorithm should not be found with given name");
        }
    }
}