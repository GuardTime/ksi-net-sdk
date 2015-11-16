using System;
using System.Collections.Generic;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Properties;
using Microsoft.Win32.SafeHandles;
using NUnit.Framework;

namespace Guardtime.KSI.Hashing
{
    [TestFixture]
    public class DataHasherTests
    {
        [Test]
        public void TestDataHasherWithDefaultAlgorithmAndEmptyData()
        {
            var hasher = new DataHasher();
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            var bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("E3-B0-C4-42-98-FC-1C-14-9A-FB-F4-C8-99-6F-B9-24-27-AE-41-E4-64-9B-93-4C-A4-95-99-1B-78-52-B8-55", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherWithDefaultAlgorithm()
        {
            var hasher = new DataHasher();
            var data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            var bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("CF-00-FC-3A-72-A2-F7-1C-7D-E2-B7-18-C0-A4-DF-F3-8D-83-C0-E1-95-7E-C2-19-C3-B2-66-F8-CC-38-B9-EA", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherWithAlternativeName()
        {
            var hasher = new DataHasher(HashAlgorithm.GetByName("sha-2"));
            var data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            var bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("CF-00-FC-3A-72-A2-F7-1C-7D-E2-B7-18-C0-A4-DF-F3-8D-83-C0-E1-95-7E-C2-19-C3-B2-66-F8-CC-38-B9-EA", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherWithDefaultAlgorithmAndByteLength()
        {
            var hasher = new DataHasher();
            var data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data, 0, data.Length);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            var bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("CF-00-FC-3A-72-A2-F7-1C-7D-E2-B7-18-C0-A4-DF-F3-8D-83-C0-E1-95-7E-C2-19-C3-B2-66-F8-CC-38-B9-EA", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherReset()
        {
            var hasher = new DataHasher();
            var data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data, 0, data.Length);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");

            var bytes = new byte[hasher.GetHash().Value.Length];
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
            var hasher = new DataHasher(HashAlgorithm.Ripemd160);
            Assert.AreEqual(HashAlgorithm.Ripemd160.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            var bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("9C-11-85-A5-C5-E9-FC-54-61-28-08-97-7E-E8-F5-48-B2-25-8D-31", BitConverter.ToString(bytes), "Hash value should be calculated correctly");
        }

        [Test]
        public void TestDataHasherWithDefaultAlgorithmAndSafeFileHandle()
        {
            var hasher = new DataHasher();
            var stream = new FileStream(Resources.DataHasher_TestFile, FileMode.Open);
            hasher.AddData(stream.SafeFileHandle);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            var bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("54-66-E3-CB-A1-4A-84-3A-5E-93-B7-8E-3D-6A-B8-D3-49-1E-DC-AC-7E-06-43-1C-E1-A7-F4-98-28-C3-40-C3", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
            stream.Close();
        }

        [Test]
        public void TestDataHasherWithDefaultAlgorithmAndFileStream()
        {
            var hasher = new DataHasher();
            var stream = new FileStream(Resources.DataHasher_TestFile, FileMode.Open);
            hasher.AddData(stream);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            var bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("54-66-E3-CB-A1-4A-84-3A-5E-93-B7-8E-3D-6A-B8-D3-49-1E-DC-AC-7E-06-43-1C-E1-A7-F4-98-28-C3-40-C3", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
            stream.Close();
        }

        [Test]
        public void TestDataHasherWithDefaultAlgorithmAndFileStreamLimitedBuffer()
        {
            var hasher = new DataHasher();
            var stream = new FileStream(Resources.DataHasher_TestFile, FileMode.Open);
            hasher.AddData(stream, 1);
            Assert.AreEqual(HashAlgorithm.Sha2256.Length, hasher.GetHash().Value.Length, "Hash length should be correct");
            var bytes = new byte[hasher.GetHash().Value.Length];
            hasher.GetHash().Value.CopyTo(bytes, 0);
            Assert.AreEqual("54-66-E3-CB-A1-4A-84-3A-5E-93-B7-8E-3D-6A-B8-D3-49-1E-DC-AC-7E-06-43-1C-E1-A7-F4-98-28-C3-40-C3", BitConverter.ToString(bytes),
                "Hash value should be calculated correctly");
            stream.Close();
        }

        [Test]
        public void TestDataHasherWithAlgorithmNull()
        {
            Assert.Throws<HashingException>(delegate
            {
                new DataHasher(null);
            });
        }

        [Test]
        public void TestDataHasherWithAlgorithmNotImplemented()
        {
            Assert.Throws<HashingException>(delegate
            {
                new DataHasher(HashAlgorithm.Sha3256);
            });
        }

        [Test]
        public void TestDataHasherWithNullBytes()
        {
            var hasher = new DataHasher();
            Assert.Throws<HashingException>(delegate
            {
                hasher.AddData((byte[])null);
            });
        }

        [Test]
        public void TestDataHasherWithNullICollection()
        {
            var hasher = new DataHasher();
            Assert.Throws<HashingException>(delegate
            {
                hasher.AddData((byte[])null);
            });
        }

        [Test]
        public void TestDataHasherWithNullBytesAndNoLength()
        {
            var hasher = new DataHasher();
            Assert.Throws<HashingException>(delegate
            {
                hasher.AddData(null, 0, 0);
            });
        }

        [Test]
        public void TestDataHasherWithNullSafeFileHandle()
        {
            var hasher = new DataHasher();
            Assert.Throws<HashingException>(delegate
            {
                hasher.AddData((SafeFileHandle)null);
            });
        }

        [Test]
        public void TestDataHasherWithNullStream()
        {
            var hasher = new DataHasher();
            Assert.Throws<HashingException>(delegate
            {
                hasher.AddData((Stream)null);
            });
        }

        [Test]
        public void TestDataHasherWithAddingDataAfterHashHasBeenCalculated()
        {
            var hasher = new DataHasher();
            var data = System.Text.Encoding.UTF8.GetBytes(Resources.DataHasher_TestString);
            hasher.AddData(data);
            hasher.GetHash();
            Assert.Throws<HashingException>(delegate
            {
                hasher.AddData(data);
            });
        }
    }
}