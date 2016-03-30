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
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Guardtime.KSI.Hashing;
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
    public class LocalAggregationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void MakeTreeTest(Ksi ksi)
        {
            Random random = new Random();

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            for (int k = 1; k < 30; k++)
            {
                byte[] buffer = new byte[10];
                List<LocalAggregationItem> aggregationItems = new List<LocalAggregationItem>();
                for (int i = 0; i < k; i++)
                {
                    IDataHasher hasher = KsiProvider.CreateDataHasher();
                    random.NextBytes(buffer);
                    hasher.AddData(buffer);
                    aggregationItems.Add(new LocalAggregationItem(hasher.GetHash(), metaData));
                }

                LocalAggregator aggregator = new LocalAggregator(aggregationItems.ToArray(), ksi);

                Console.WriteLine("Document count: " + aggregationItems.Count);
                Console.WriteLine("Tree: " + aggregator.PrintTree());
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void PrintTreeTest(Ksi ksi)
        {
            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");
            List<LocalAggregationItem> aggregationItems = new List<LocalAggregationItem>();

            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382")), metaData));

            LocalAggregator aggregator = new LocalAggregator(aggregationItems.ToArray(), ksi);

            Console.WriteLine("Document count: " + aggregationItems.Count);
            Console.WriteLine("Tree: \"" + aggregator.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                                                                          
                                                                                          4R:01AEF61  
                                                  / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                                          3L:0167E02                                                                                      
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                                               \        
                  2L:01BD80B                                      2R:0143A80                                      2R:01F154F  
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
      1L:01C1E49              1R:0116478              1L:01E94E1              1R:011AD22              1L:01934A0              
        /    \                  /    \                  /    \                  /    \                  /    \           \        
0L:0109A9F  0R:01BEC84  0L:01C734E  0R:01B0CF0  0L:01BB95E  0R:017943B  0L:0123C4A  0R:01A360B  0L:010347A  0R:0178C63  0R:010579A  
",
                aggregator.PrintTree());
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void PrintTreeTest2(Ksi ksi)
        {
            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");
            List<LocalAggregationItem> aggregationItems = new List<LocalAggregationItem>();

            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD")), metaData));
            aggregationItems.Add(new LocalAggregationItem(new DataHash(Base16.Decode("01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA")), metaData));

            LocalAggregator aggregator = new LocalAggregator(aggregationItems.ToArray(), ksi);

            Console.WriteLine("Document count: " + aggregationItems.Count);
            Console.WriteLine("Tree: \"" + aggregator.PrintTree() + "\"");
            Assert.AreEqual(
                @"                                          
                                          3R:0114439  
                          / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \        
                  2L:01BD80B                                      
              / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                      
      1L:01C1E49              1R:0116478              
        /    \                  /    \           \        
0L:0109A9F  0R:01BEC84  0L:01C734E  0R:01B0CF0  0R:01BB95E  
",
                aggregator.PrintTree());
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void LocalAggregationTest(Ksi ksi)
        {
            int k = 11;
            Random random = new Random();
            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id", "test machine id");
            List<LocalAggregationItem> aggregationItems = new List<LocalAggregationItem>();

            byte[] buffer = new byte[10];

            for (int i = 0; i < k; i++)
            {
                IDataHasher hasher = KsiProvider.CreateDataHasher();
                random.NextBytes(buffer);
                hasher.AddData(buffer);
                aggregationItems.Add(new LocalAggregationItem(hasher.GetHash(), metaData));
            }

            LocalAggregator aggregator = new LocalAggregator(aggregationItems.ToArray(), ksi);

            LocalAggregationItem[] result = aggregator.SignDocuments();

            foreach (LocalAggregationItem aggregationItem in result)
            {
                Verify(ksi, aggregationItem.Signature, aggregationItem.DocumentHash);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void LocalAggregationTest2(Ksi ksi)
        {
            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");
            List<LocalAggregationItem> aggregationItems = new List<LocalAggregationItem>
            {
                new LocalAggregationItem(new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")), metaData),
                new LocalAggregationItem(new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")), metaData),
                new LocalAggregationItem(new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")), metaData)
            };

            LocalAggregator aggregator = new LocalAggregator(aggregationItems.ToArray(), ksi);

            Console.WriteLine("Tree: " + aggregator.PrintTree());

            LocalAggregationItem[] result = aggregator.SignDocuments();

            foreach (LocalAggregationItem aggregationItem in result)
            {
                Verify(ksi, aggregationItem.Signature, aggregationItem.DocumentHash);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void LocalAggregationParallelTest(Ksi ksi)
        {
            ManualResetEvent waitHandle = new ManualResetEvent(false);

            int[] treeSizes = new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 101, 102, 103, 104, 105 };
            int doneCount = 0;
            int runCount = treeSizes.Length;
            string errorMessage = null;

            Random random = new Random();

            AggregationHashChain.MetaData metaData = new AggregationHashChain.MetaData("test client id");

            foreach (int j in treeSizes)
            {
                int k = j;

                Task.Run(() =>
                {
                    Console.WriteLine("Document count: " + k);

                    List<LocalAggregationItem> aggregationItems = new List<LocalAggregationItem>();

                    byte[] buffer = new byte[10];

                    for (int i = 0; i < k; i++)
                    {
                        IDataHasher hasher = KsiProvider.CreateDataHasher();
                        random.NextBytes(buffer);
                        hasher.AddData(buffer);
                        aggregationItems.Add(new LocalAggregationItem(hasher.GetHash(), metaData));
                    }

                    try
                    {
                        LocalAggregator aggregator = new LocalAggregator(aggregationItems.ToArray(), ksi);

                        LocalAggregationItem[] result = aggregator.SignDocuments();

                        foreach (LocalAggregationItem aggregationItem in result)
                        {
                            Verify(ksi, aggregationItem.Signature, aggregationItem.DocumentHash);
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

        private static void Verify(Ksi ksi, IKsiSignature signature, DataHash documentHashm)
        {
            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = documentHashm,
                PublicationsFile = ksi.GetPublicationsFile()
            };

            KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

            VerificationResult verificationResult = policy.Verify(verificationContext);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }
    }
}