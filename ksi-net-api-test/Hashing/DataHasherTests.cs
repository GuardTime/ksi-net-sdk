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
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using NUnit.Framework;

// ReSharper disable ObjectCreationAsStatement

namespace Guardtime.KSI.Test.Hashing
{
    [TestFixture]
    public class DataHasherTests
    {
        [Test]
        public void TestDataHasherWithDefaultAlgorithmAndEmptyData()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            byte[] bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("E3-B0-C4-42-98-FC-1C-14-9A-FB-F4-C8-99-6F-B9-24-27-AE-41-E4-64-9B-93-4C-A4-95-99-1B-78-52-B8-55", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherWithDefaultAlgorithm()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            byte[] data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            byte[] bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("CF-00-FC-3A-72-A2-F7-1C-7D-E2-B7-18-C0-A4-DF-F3-8D-83-C0-E1-95-7E-C2-19-C3-B2-66-F8-CC-38-B9-EA", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherWithAlternativeName()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher(HashAlgorithm.GetByName("sha-2"));
            byte[] data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            byte[] bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("CF-00-FC-3A-72-A2-F7-1C-7D-E2-B7-18-C0-A4-DF-F3-8D-83-C0-E1-95-7E-C2-19-C3-B2-66-F8-CC-38-B9-EA", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherWithDefaultAlgorithmAndByteLength()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            byte[] data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data, 0, data.Length);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            byte[] bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("CF-00-FC-3A-72-A2-F7-1C-7D-E2-B7-18-C0-A4-DF-F3-8D-83-C0-E1-95-7E-C2-19-C3-B2-66-F8-CC-38-B9-EA", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherReset()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            byte[] data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data, 0, data.Length);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");

            byte[] bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("CF-00-FC-3A-72-A2-F7-1C-7D-E2-B7-18-C0-A4-DF-F3-8D-83-C0-E1-95-7E-C2-19-C3-B2-66-F8-CC-38-B9-EA", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
            hasher.Reset();
            hasher.AddData(data, 0, data.Length);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");

            bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("CF-00-FC-3A-72-A2-F7-1C-7D-E2-B7-18-C0-A4-DF-F3-8D-83-C0-E1-95-7E-C2-19-C3-B2-66-F8-CC-38-B9-EA", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherWithRipemd160Algorithm()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher(HashAlgorithm.Ripemd160);
            Assert.AreEqual(HashAlgorithm.Ripemd160.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            byte[] bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("9C-11-85-A5-C5-E9-FC-54-61-28-08-97-7E-E8-F5-48-B2-25-8D-31", BitConverter.ToString(bytes), "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherWithDefaultAlgorithmAndFileStream()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.DataHasher_TestFile), FileMode.Open);
            hasher.AddData(stream);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            byte[] bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("54-66-E3-CB-A1-4A-84-3A-5E-93-B7-8E-3D-6A-B8-D3-49-1E-DC-AC-7E-06-43-1C-E1-A7-F4-98-28-C3-40-C3", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
            stream.Close();
        }

        [Test]
        public void TestDataHasherWithDefaultAlgorithmAndFileStreamLimitedBuffer()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.DataHasher_TestFile), FileMode.Open);
            hasher.AddData(stream, 1);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            byte[] bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("54-66-E3-CB-A1-4A-84-3A-5E-93-B7-8E-3D-6A-B8-D3-49-1E-DC-AC-7E-06-43-1C-E1-A7-F4-98-28-C3-40-C3", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
            stream.Close();
        }

        [Test]
        public void TestDataHasherWithAlgorithmNull()
        {
            Assert.Throws<ArgumentNullException>(delegate
            {
                CryptoTestFactory.CreateDataHasher(null);
            });
        }

        [Test]
        public void TestDataHasherWithAlgorithmNotImplemented()
        {
            Assert.Throws<HashingException>(delegate
            {
                CryptoTestFactory.CreateDataHasher(HashAlgorithm.Sha3256);
            });
        }

        [Test]
        public void TestDataHasherWithNullBytes()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            Assert.Throws<ArgumentNullException>(delegate
            {
                hasher.AddData((byte[])null);
            });
        }

        [Test]
        public void TestDataHasherWithNullICollection()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            Assert.Throws<ArgumentNullException>(delegate
            {
                hasher.AddData((byte[])null);
            });
        }

        [Test]
        public void TestDataHasherWithNullBytesAndNoLength()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            Assert.Throws<ArgumentNullException>(delegate
            {
                hasher.AddData(null, 0, 0);
            });
        }

        [Test]
        public void TestDataHasherWithNullStream()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            Assert.Throws<ArgumentNullException>(delegate
            {
                hasher.AddData((Stream)null);
            });
        }

        [Test]
        public void TestDataHasherWithAddingDataAfterHashHasBeenCalculated()
        {
            IDataHasher hasher = CryptoTestFactory.CreateDataHasher();
            byte[] data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data);
            hasher.GetHash();
            Assert.Throws<HashingException>(delegate
            {
                hasher.AddData(data);
            });
        }
    }
}