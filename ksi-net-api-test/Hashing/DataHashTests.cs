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
using Guardtime.KSI.Hashing;
using NUnit.Framework;

// ReSharper disable ObjectCreationAsStatement

namespace Guardtime.KSI.Test.Hashing
{
    [TestFixture]
    public class DataHashTests
    {
        [Test]
        public void TestDataHashFromAlgorithmAndValue()
        {
            DataHash dataHash = new DataHash(HashAlgorithm.Sha2256,
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });
            Assert.AreEqual(HashAlgorithm.Sha2256, dataHash.Algorithm, "Algorithm should be preserved");
            CollectionAssert.AreEqual(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 },
                dataHash.Imprint, "Hash imprint should be created correctly");
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 },
                dataHash.Value, "Hash value should be preserved");
            Assert.AreEqual("SHA-256:[0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20]", dataHash.ToString(),
                "Hash string representation should be in correct format");
        }

        [Test]
        public void TestDataHashFromImprint()
        {
            DataHash dataHash = new DataHash(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });
            Assert.AreEqual(HashAlgorithm.Sha2256, dataHash.Algorithm, "Algorithm should be preserved");
            CollectionAssert.AreEqual(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 },
                dataHash.Imprint, "Hash imprint should be created correctly");
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 },
                dataHash.Value, "Hash value should be preserved");
            Assert.AreEqual("SHA-256:[0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20]", dataHash.ToString(),
                "Hash string representation should be in correct format");
        }

        [Test]
        public void TestDataHashEquals()
        {
            DataHash dataHash = new DataHash(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });
            Assert.IsTrue(
                dataHash.Equals(new DataHash(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                "Hash should be equal to itself");
            Assert.IsFalse(
                dataHash.Equals(
                    new ChildDataHash(new byte[] { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })));
            Assert.IsFalse(dataHash.Equals(null), "Hash should not equal to null");
            Assert.IsFalse(dataHash.Equals(new object()), "Hash should not equal to empty object");
            Assert.AreEqual(
                new DataHash(HashAlgorithm.Sha2256,
                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }), dataHash,
                "Hash should be equal to similar hash algorithm and value");
            Assert.AreEqual("SHA-256:[0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20]", dataHash.ToString(),
                "Hash string representation should be in correct format");
        }

        [Test]
        public void TestDataHashCreateWithNullAlgorithm()
        {
            Assert.Throws<ArgumentNullException>(delegate
            {
                new DataHash(null, new byte[] { });
            });
        }

        [Test]
        public void TestDataHashCreateWithNullValue()
        {
            Assert.Throws<ArgumentNullException>(delegate
            {
                new DataHash(HashAlgorithm.Sha2256, null);
            });
        }

        [Test]
        public void TestDataHashCreateWithInvalidValueLength()
        {
            Assert.Throws<HashingException>(delegate
            {
                new DataHash(HashAlgorithm.Sha2256, new byte[] { });
            });
        }

        [Test]
        public void TestDataHashCreateWithNullBytes()
        {
            Assert.Throws<ArgumentNullException>(delegate
            {
                new DataHash(null);
            });
        }

        [Test]
        public void TestDataHashCreateWithZeroLengthBytes()
        {
            Assert.Throws<HashingException>(delegate
            {
                new DataHash(new byte[] { });
            });
        }

        [Test]
        public void TestDataHashCreateWithInvalidAlgorithmFromBytes()
        {
            Assert.Throws<HashingException>(delegate
            {
                new DataHash(new byte[] { 255 });
            });
        }

        [Test]
        public void TestDataHashCreateWithInvalidValueLengthFromBytes()
        {
            Assert.Throws<HashingException>(delegate
            {
                new DataHash(new byte[] { 1, 1, 2, 3, 4, 5, 6 });
            });
        }

        private class ChildDataHash : DataHash
        {
            public ChildDataHash(byte[] imprintBytes) : base(imprintBytes)
            {
            }
        }
    }
}