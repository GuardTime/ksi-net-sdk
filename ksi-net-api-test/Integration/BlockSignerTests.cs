/*
 * Copyright 2013-2016 Guardtime, Inc.
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
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public partial class BlockSignerTests : IntegrationTests
    {
        /// <summary>
        /// Testing getting uni-signatures of lots of randomly generated hashes
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerGetUniSignaturesOfManyRandomHashesTest(Ksi ksi)
        {
            int k = 8;
            Random random = new Random();
            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id", "test machine id");
            List<DataHash> hashes = new List<DataHash>();
            byte[] buffer = new byte[10];

            for (int i = 0; i < k; i++)
            {
                IDataHasher hasher = KsiProvider.CreateDataHasher();
                random.NextBytes(buffer);
                hasher.AddData(buffer);
                hashes.Add(hasher.GetHash());
            }

            Console.WriteLine(DateTime.Now + ": Start creating local blockSigner.");
            BlockSigner blockSigner = new BlockSigner(ksi);

            foreach (DataHash hash in hashes)
            {
                blockSigner.AddDocument(hash, metadata);
            }

            Console.WriteLine(DateTime.Now + ": Sign documents.");
            IEnumerable<RawTag> uniSignatures = blockSigner.GetUniSignatures();
            Console.WriteLine(DateTime.Now + ": Start verifying.");
            int n = 0;

            foreach (RawTag signature in uniSignatures)
            {
                Verify(ksi, new KsiSignature(signature), hashes[n++]);
            }
        }

        /// <summary>
        /// Testing getting uni-signatures of given hashes.
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerGetUniSignaturesOfGivenHashesTest(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi);
            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");
            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB"))
            };

            foreach (DataHash hash in hashes)
            {
                blockSigner.AddDocument(hash, metadata);
            }

            int i = 0;

            foreach (RawTag signature in blockSigner.GetUniSignatures())
            {
                KsiSignature ksiSignature = new KsiSignature(signature);
                VerifyChainAlgorithm(ksiSignature, HashAlgorithm.Default);
                Verify(ksi, ksiSignature, hashes[i++]);
            }
        }

        /// <summary>
        /// Testing getting uni-signatures of given hashes.
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerGetUniSignaturesOfGivenHashesWithSha1Test(Ksi ksi)
        {
            BlockSigner blockSigner = new BlockSigner(ksi, HashAlgorithm.Sha1);
            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");
            List<DataHash> hashes = new List<DataHash>
            {
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB"))
            };

            foreach (DataHash hash in hashes)
            {
                blockSigner.AddDocument(hash, metadata);
            }

            int i = 0;

            foreach (RawTag signature in blockSigner.GetUniSignatures())
            {
                KsiSignature ksiSignature = new KsiSignature(signature);
                VerifyChainAlgorithm(ksiSignature, HashAlgorithm.Sha1);
                Verify(ksi, ksiSignature, hashes[i++]);
            }
        }

        private static void VerifyChainAlgorithm(IKsiSignature ksiSignature, HashAlgorithm expecgedAloAlgorithm)
        {
            AggregationHashChain aggregationHashChain = ksiSignature.GetAggregationHashChains()[0];
            IntegerTag id = aggregationHashChain.GetType().InvokeMember("_aggrAlgorithmId", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.GetField, null,
                aggregationHashChain, null) as IntegerTag;
            Assert.AreEqual(expecgedAloAlgorithm.Id, id.Value, "Aggregation hash chain hash algorithm should match");
        }

        /// <summary>
        /// Test getting uni-signatures in parallel threads
        /// </summary>
        /// <param name="ksi"></param>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void BlockSignerGetUniSignaturesParallelTest(Ksi ksi)
        {
            ManualResetEvent waitHandle = new ManualResetEvent(false);

            int[] treeSizes = new[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            int doneCount = 0;
            int runCount = treeSizes.Length;
            string errorMessage = null;

            Random random = new Random();

            AggregationHashChain.Metadata metadata = new AggregationHashChain.Metadata("test client id");

            foreach (int j in treeSizes)
            {
                int k = j;

                Task.Run(() =>
                {
                    Console.WriteLine("Document count: " + k);

                    BlockSigner blockSigner = new BlockSigner(ksi);
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
                        blockSigner.AddDocument(hash, metadata);
                    }

                    try
                    {
                        int i = 0;

                        foreach (RawTag signature in blockSigner.GetUniSignatures())
                        {
                            Verify(ksi, new KsiSignature(signature), hashes[i++]);
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

            KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            VerificationResult verificationResult = policy.Verify(verificationContext);
            if (verificationResult.ResultCode != VerificationResultCode.Ok)
            {
                Console.WriteLine("Verification result code: " + verificationResult.ResultCode);
                Console.WriteLine("Verification rule name: " + verificationResult.RuleName);
                Console.WriteLine("Verification error: " + verificationResult.VerificationError);
            }
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }
    }
}