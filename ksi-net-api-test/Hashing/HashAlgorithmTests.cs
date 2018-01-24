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

using System.Collections.Generic;
using System.Linq;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Hashing
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
        public void TestAlgorithmGetByIdInvalid()
        {
            Assert.That(delegate
            {
                HashAlgorithm.GetById(3);
            }, Throws.TypeOf<HashingException>().With.Message.StartWith("Invalid hash algorithm"), "Id 3 should be invalid");

            Assert.That(delegate
            {
                HashAlgorithm.GetById(0x7E);
            }, Throws.TypeOf<HashingException>().With.Message.StartWith("Invalid hash algorithm"), "Id 7E should be invalid");
        }

        [Test]
        public void TestAlgorithmGetByName()
        {
            HashAlgorithm algorithm = HashAlgorithm.Default;
            Assert.AreEqual(1u, algorithm.Id, "Hash algorithm id should be correct");
            Assert.AreEqual("SHA-256", algorithm.Name, "Hash algorithm name should be correct");
            Assert.AreEqual(HashAlgorithm.AlgorithmStatus.Normal, algorithm.Status, "Hash algorithm status should be correct");
            Assert.AreEqual(32, algorithm.Length, "Hash algorithm length should be correct");
        }

        [Test]
        public void TestGetNamesList()
        {
            IEnumerable<string> names = HashAlgorithm.GetNamesList();
            Assert.AreEqual(10, names.Count());
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