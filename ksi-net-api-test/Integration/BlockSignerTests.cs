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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Signature.Verification.Rule;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class BlockSignerTests : IntegrationTests
    {
        /// <summary>
        /// Testing getting uni-signatures of lots of randomly generated hashes
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerGetUniSignaturesOfManyRandomHashesTest(Ksi ksi)
        {
            int k = 7;
            Random random = new Random();
            IdentityMetadata metadata = new IdentityMetadata("test client id", "test machine id");
            List<DataHash> hashes = new List<DataHash>();
            byte[] buffer = new byte[10];

            for (int i = 0; i < k; i++)
            {
                IDataHasher hasher = KsiProvider.CreateDataHasher();
                random.NextBytes(buffer);
                hasher.AddData(buffer);
                hashes.Add(hasher.GetHash());
            }

            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService());

            foreach (DataHash hash in hashes)
            {
                blockSigner.Add(hash, metadata);
            }

            IEnumerable<IKsiSignature> uniSignatures = blockSigner.Sign();
            int n = 0;

            foreach (IKsiSignature signature in uniSignatures)
            {
                Verify(ksi, signature, hashes[n++]);
            }
        }

        /// <summary>
        /// Testing getting uni-signatures of given hashes.
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerGetUniSignaturesOfGivenHashesTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService());
            IdentityMetadata metadata = new IdentityMetadata("test client id");
            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB"))
            };

            foreach (DataHash hash in hashes)
            {
                blockSigner.Add(hash, metadata);
            }

            int i = 0;

            foreach (IKsiSignature ksiSignature in blockSigner.Sign())
            {
                VerifyChainAlgorithm(ksiSignature, HashAlgorithm.Default);
                Verify(ksi, ksiSignature, hashes[i++]);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerSignOneHashTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService());
            DataHash hash = new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"));

            blockSigner.Add(hash);

            IEnumerator<IKsiSignature> signatures = blockSigner.Sign().GetEnumerator();
            Assert.True(signatures.MoveNext(), "Invalid signature count: 0");
            IKsiSignature signature = signatures.Current;
            Assert.False(signatures.MoveNext(), "Invalid signature count: > 1");
            Assert.Less(0, signature.GetAggregationHashChains()[0].GetChainLinks().Count, "Invalid links count.");
            Assert.AreEqual(Properties.Settings.Default.HttpSigningServiceUser, signature.GetAggregationHashChains()[0].GetChainLinks()[0].Metadata.ClientId, "Unexpected metadata.");

            VerifyChainAlgorithm(signature, HashAlgorithm.Default);
            Verify(ksi, signature, hash);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerSignOneHashWithLevelTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService());
            DataHash hash = new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"));

            blockSigner.Add(hash, null, 2);

            IEnumerator<IKsiSignature> signatures = blockSigner.Sign().GetEnumerator();
            Assert.True(signatures.MoveNext(), "Invalid signature count: 0");
            IKsiSignature signature = signatures.Current;
            Assert.False(signatures.MoveNext(), "Invalid signature count: > 1");
            Assert.Less(0, signature.GetAggregationHashChains()[0].GetChainLinks().Count, "Invalid links count.");
            Assert.AreEqual(Properties.Settings.Default.HttpSigningServiceUser, signature.GetAggregationHashChains()[0].GetChainLinks()[0].Metadata.ClientId, "Unexpected metadata.");
            Assert.LessOrEqual(2, signature.GetAggregationHashChains()[0].GetChainLinks()[0].LevelCorrection, "Level correction is invalid.");

            VerifyChainAlgorithm(signature, HashAlgorithm.Default);
            Verify(ksi, signature, hash);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerSignOneWithMetadaHashTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService());
            DataHash hash = new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"));
            IdentityMetadata metadata = new IdentityMetadata("test client id");

            blockSigner.Add(hash, metadata);

            IEnumerator<IKsiSignature> signatures = blockSigner.Sign().GetEnumerator();
            Assert.True(signatures.MoveNext(), "Invalid signature count: 0");
            IKsiSignature signature = signatures.Current;
            Assert.False(signatures.MoveNext(), "Invalid signature count: > 1");
            Assert.AreEqual(1, signature.GetAggregationHashChains()[0].GetChainLinks().Count, "Invalid links count.");
            Assert.AreEqual(metadata.ClientId, signature.GetAggregationHashChains()[0].GetChainLinks()[0].Metadata.ClientId, "Invalid metadata.");

            VerifyChainAlgorithm(signature, HashAlgorithm.Default);
            Verify(ksi, signature, hash);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerSignOneHashWithBlindingMaskTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService(), true, new byte[] { 1, 2, 3 });
            DataHash hash = new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"));

            blockSigner.Add(hash);

            IEnumerator<IKsiSignature> signatures = blockSigner.Sign().GetEnumerator();
            Assert.True(signatures.MoveNext(), "Invalid signature count: 0");
            IKsiSignature signature = signatures.Current;
            Assert.False(signatures.MoveNext(), "Invalid signature count: > 1");
            Assert.Less(0, signature.GetAggregationHashChains()[0].GetChainLinks().Count, "Invalid links count.");
            Assert.IsNull(signature.GetAggregationHashChains()[0].GetChainLinks()[0].Metadata, "Unexpected right sibling type.");

            VerifyChainAlgorithm(signature, HashAlgorithm.Default);
            Verify(ksi, signature, hash);
        }

        /// <summary>
        /// Testing getting uni-signatures of given hashes wiht given level
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerGetUniSignaturesOfGivenHashesWithLevelTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService());
            IdentityMetadata metadata = new IdentityMetadata("test client id");
            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")),
                new DataHash(Base16.Decode("01680192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")),
                new DataHash(Base16.Decode("019D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")),
                new DataHash(Base16.Decode("0124F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32EC3")),
                new DataHash(Base16.Decode("0134F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32EC4"))
            };

            List<uint> levels = new List<uint>() { 1, 2, 3, 0, 4, 2, 2 };
            List<bool> hasMetadata = new List<bool>() { true, false, false, false, true, true, true, false };
            int i = 0;

            foreach (DataHash hash in hashes)
            {
                blockSigner.Add(hash, hasMetadata[i] ? metadata : null, levels[i++]);
            }

            i = 0;

            foreach (IKsiSignature ksiSignature in blockSigner.Sign())
            {
                VerifyChainAlgorithm(ksiSignature, HashAlgorithm.Default);
                Verify(ksi, ksiSignature, hashes[i]);
                i++;
            }
        }

        /// <summary>
        /// Testing getting uni-signatures of given hashes wiht given level
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerGetUniSignaturesOfGivenHashesWithLevelAndBlindingMaskTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService(), true, new byte[] { 1, 2, 3 });
            IdentityMetadata metadata = new IdentityMetadata("test client id");
            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01A80192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("01AD982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("01A4F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")),
                new DataHash(Base16.Decode("01A80192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")),
                new DataHash(Base16.Decode("01AD982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")),
                new DataHash(Base16.Decode("01A4F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32EC3")),
                new DataHash(Base16.Decode("01A4F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32EC4"))
            };

            List<uint> levels = new List<uint>() { 3, 2, 5, 0, 1, 2, 0 };
            List<bool> hasMetadata = new List<bool>() { false, false, true, true, false, true, true, false };
            int i = 0;

            foreach (DataHash hash in hashes)
            {
                blockSigner.Add(hash, hasMetadata[i] ? metadata : null, levels[i++]);
            }

            i = 0;

            foreach (IKsiSignature ksiSignature in blockSigner.Sign())
            {
                VerifyChainAlgorithm(ksiSignature, HashAlgorithm.Default);
                Verify(ksi, ksiSignature, hashes[i++]);
            }
        }

        /// <summary>
        /// Testing custom signature factory. Automatic verification fails.
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerCustomSignatureFactoryTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService(), null, new KsiSignatureFactory(
                new PublicationBasedVerificationPolicy(),
                new TestVerificationContext()
                {
                    UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AANGVK-SV7GJL-36LN65-AVJYZR-6XRZSL-HIMRH3-6GU7WR-YNRY7C-X2XECY-WFQXRB")
                }));

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            DataHash documentHash = new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"));
            blockSigner.Add(documentHash, metadata);

            Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                blockSigner.Sign().GetEnumerator().MoveNext();
            }, "Automatic verification should fail.");
        }

        /// <summary>
        /// Testing getting uni-signatures of given hashes.
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerGetUniSignaturesOfGivenHashesWithSha512Test(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(GetHttpKsiService(), HashAlgorithm.Sha2512);
            IdentityMetadata metadata = new IdentityMetadata("test client id");
            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB"))
            };

            foreach (DataHash hash in hashes)
            {
                blockSigner.Add(hash, metadata);
            }

            int i = 0;

            foreach (IKsiSignature ksiSignature in blockSigner.Sign())
            {
                VerifyChainAlgorithm(ksiSignature, HashAlgorithm.Sha2512);
                Verify(ksi, ksiSignature, hashes[i++]);
            }
        }

        /// <summary>
        /// Testing with deprecated hash algorithm
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void BlockSignerWithDeprecatedHashAlgorithmTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<HashingException>(delegate
            {
                new BlockSigner(GetHttpKsiService(), HashAlgorithm.Sha1);
            });

            Assert.That(ex.Message.StartsWith("Hash algorithm SHA1 is deprecated since 2016-07-01 and can not be used."),
                "Unexpected exception message: " + ex.Message);
        }

        private static void VerifyChainAlgorithm(IKsiSignature ksiSignature, HashAlgorithm expectedAlgorithm)
        {
            AggregationHashChain aggregationHashChain = ksiSignature.GetAggregationHashChains()[0];
            Assert.AreEqual(expectedAlgorithm.Id, aggregationHashChain.AggregationAlgorithm.Id, "Aggregation hash chain hash algorithm should match");
        }

        /// <summary>
        /// Test getting uni-signatures in parallel threads
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerGetUniSignaturesParallelTest(Ksi ksi)
        {
            ManualResetEvent waitHandle = new ManualResetEvent(false);

            int[] treeSizes = new[] { 1, 2, 3, 4, 5 };
            int doneCount = 0;
            int runCount = treeSizes.Length;
            string errorMessage = null;

            Random random = new Random();

            IdentityMetadata metadata = new IdentityMetadata("test client id");

            foreach (int j in treeSizes)
            {
                int k = j;

                Task.Run(() =>
                {
                    Console.WriteLine("Document count: " + k);

                    BlockSigner blockSigner = new BlockSigner(GetHttpKsiService());
                    List<DataHash> hashes = new List<DataHash>();

                    byte[] buffer = new byte[10];

                    for (int i = 0; i < k; i++)
                    {
                        IDataHasher hasher = KsiProvider.CreateDataHasher();
                        random.NextBytes(buffer);
                        hasher.AddData(buffer);
                        hashes.Add(hasher.GetHash());
                    }

                    foreach (DataHash hash in hashes)
                    {
                        blockSigner.Add(hash, metadata);
                    }

                    try
                    {
                        int i = 0;

                        foreach (IKsiSignature ksiSignature in blockSigner.Sign())
                        {
                            Verify(ksi, ksiSignature, hashes[i++]);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " Error " + k + ". " + ex);
                        if (errorMessage == null)
                        {
                            errorMessage = ex.ToString();
                        }
                    }
                    finally
                    {
                        doneCount++;

                        Console.WriteLine("Done " + k);

                        if (doneCount == runCount)
                        {
                            waitHandle.Set();
                        }
                    }
                });
            }

            Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " Waiting ...");

            waitHandle.WaitOne();

            if (errorMessage != null)
            {
                Assert.Fail("ERROR: " + errorMessage);
            }

            Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " All done.");
        }

        private static void Verify(Ksi ksi, IKsiSignature signature, DataHash documentHash)
        {
            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = documentHash,
                PublicationsFile = ksi.GetPublicationsFile()
            };

            AggregationHashChain.Link firstChainLink = signature.GetAggregationHashChains()[0].GetChainLinks()[0];
            if (firstChainLink.Metadata != null && firstChainLink.Metadata.Padding == null)
            {
                throw new Exception("Metadata padding is missing.");
            }

            KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy();

            VerificationResult verificationResult = policy.Verify(verificationContext);
            if (verificationResult.ResultCode != VerificationResultCode.Ok)
            {
                Console.WriteLine("Verification result code: " + verificationResult.ResultCode);
                Console.WriteLine("Verification rule name: " + verificationResult.RuleName);
                Console.WriteLine("Verification error: " + verificationResult.VerificationError);
            }
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }

        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsi))]
        public void BlockSignerTreeHeightLimitTest(Ksi ksi)
        {
            IdentityMetadata metadata = new IdentityMetadata("test client id", "test machine id");
            DataHash hash = new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB"));

            List<HeightTestData> list = new List<HeightTestData>()
            {
                new HeightTestData(new List<uint> { 1 }, null, 0, 0),
                new HeightTestData(new List<uint> { 1, 2, 1 }, null, 3, 2),
                new HeightTestData(new List<uint> { 1, 2, 2 }, null, 3, 2),
                new HeightTestData(new List<uint> { 1, 0, 1 }, null, 2, 2),
                new HeightTestData(new List<uint> { 0, 0, 0 }, new List<bool> { true, false, true }, 2, 2),
                new HeightTestData(new List<uint> { 2, 1, 1, 1 }, null, 3, 3),
                new HeightTestData(new List<uint> { 1, 0, 0, 0 }, null, 2, 3),
                new HeightTestData(new List<uint> { 0, 0, 0, 0, 0 }, new List<bool> { true, true, true, true, true }, 3, 4),
                new HeightTestData(new List<uint> { 1, 0, 1, 0, 0, 0 }, null, 3, 5),
                new HeightTestData(new List<uint> { 0, 0, 0, 1, 0, 1, 0 }, null, 3, 5),
                new HeightTestData(new List<uint> { 0, 0, 0, 0, 0, 0 }, new List<bool> { true, false, true, false, false, false }, 3, 5),
                new HeightTestData(new List<uint> { 0, 0, 0, 0, 0, 0, 0, 0, 0 }, new List<bool> { false, false, false, false, false, false, false, false, false }, 3, 8),
                new HeightTestData(new List<uint> { 3, 3 }, new List<bool> { false, false }, 3, 1),
                new HeightTestData(new List<uint> { 3, 3 }, new List<bool> { true, true }, 3, 0),
                new HeightTestData(new List<uint> { 0, 3 }, new List<bool> { false, false }, 3, 1),
                new HeightTestData(new List<uint> { 3, 0 }, new List<bool> { false, false }, 3, 1),
                new HeightTestData(new List<uint> { 2, 0, 0, 0, 0, 0 }, null, 3, 5),
                new HeightTestData(new List<uint> { 4, 3, 2, 3, 1, 0, 3, 2, 0, 3 }, null, 6, 9),
                new HeightTestData(new List<uint> { 4, 3, 2, 3, 1, 0, 3, 2, 0, 1, 0, 0 }, null, 6, 10),
                new HeightTestData(new List<uint> { 7, 6, 5, 6, 4, 3, 6, 5, 3, 6, 8 }, null, 9, 9),
            };

            for (int index = 0; index < list.Count; index++)
            {
                HeightTestData data = list[index];
                BlockSigner blockSigner = new BlockSigner(GetHttpKsiService(), null, null, data.MaxHeight);
                bool success = false;

                Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
                Console.WriteLine("Test row: " + (index + 1));
                Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");

                for (int i = 0; i < data.Levels.Count; i++)
                {
                    Console.WriteLine("---------------------------------------------------------------------");
                    Console.WriteLine("Item: " + (i + 1) + "; Level: " + data.Levels[i] + "; Node: " + hash);
                    Console.WriteLine("---------------------------------------------------------------------");

                    IdentityMetadata meta = data.MetaExists != null && data.MetaExists.Count > i && data.MetaExists[i] ? metadata : null;
                    if (!blockSigner.Add(hash, meta, data.Levels[i]))
                    {
                        success = data.AllowedItemCount == i;
                        Assert.IsTrue(success, "Invalid height calculation. Row: " + (index + 1) + "; Node count: " + (i + 1));
                        break;
                    }
                }

                if (!success)
                {
                    Assert.Fail("Invalid height calculation.  All hashes added. Row: " + (index + 1));
                }
            }
        }

        private class HeightTestData
        {
            public List<uint> Levels { get; }
            public List<bool> MetaExists { get; }
            public uint MaxHeight { get; }
            public uint AllowedItemCount { get; }

            public HeightTestData(List<uint> levels, List<bool> metaExists, uint maxHeight, uint allowedItemCount)
            {
                Levels = levels;
                MetaExists = metaExists;
                MaxHeight = maxHeight;
                AllowedItemCount = allowedItemCount;
            }
        }
    }
}