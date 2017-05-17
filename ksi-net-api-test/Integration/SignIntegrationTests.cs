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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class SignIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void HttpSignHashTest(Ksi ksi)
        {
            VerificationResult verificationResult = SignHash(ksi);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void HttpSignHashWithLevelTest(Ksi ksi)
        {
            DataHash documentHash = new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));

            IKsiSignature signature = ksi.Sign(documentHash, 3);

            Assert.LessOrEqual(3, signature.GetAggregationHashChains()[0].GetChainLinks()[0].LevelCorrection, "Level correction is invalid.");

            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = documentHash,
                PublicationsFile = ksi.GetPublicationsFile()
            };
            KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));
            VerificationResult verificationResult = policy.Verify(verificationContext);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void HttpSignByteArrayTest(Ksi ksi)
        {
            byte[] data = Encoding.UTF8.GetBytes("This is my document");
            IKsiSignature signature = ksi.Sign(data);

            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = new DataHash(HashAlgorithm.Sha2256,
                    Base16.Decode("D439459856BEF5ED25772646F73A70A841FC078D3CBBC24AB7F47C464683768D")),
                PublicationsFile = ksi.GetPublicationsFile()
            };
            KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));
            VerificationResult verificationResult = policy.Verify(verificationContext);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void HttpSignWithStreamTest(Ksi ksi)
        {
            IKsiSignature signature;
            using (MemoryStream stream = new MemoryStream())
            {
                byte[] data = Encoding.UTF8.GetBytes("This is my document");
                stream.Write(data, 0, data.Length);
                stream.Seek(0, SeekOrigin.Begin);
                signature = ksi.Sign(stream);
            }

            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = new DataHash(HashAlgorithm.Sha2256,
                    Base16.Decode("D439459856BEF5ED25772646F73A70A841FC078D3CBBC24AB7F47C464683768D")),
                PublicationsFile = ksi.GetPublicationsFile()
            };
            KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));
            VerificationResult verificationResult = policy.Verify(verificationContext);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidSigningPass))]
        public void HttpSignHashInvalidPassTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceException>(delegate
            {
                SignHash(ksi);
            });

            Assert.AreEqual("Server responded with error message. Status: 258; Message: The request could not be authenticated.", ex.Message);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidSigningUrl))]
        public void HttpSignHashInvalidUrlTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                SignHash(ksi);
            });

            Assert.That(ex.Message.StartsWith("Request failed"), "Unexpected exception message: " + ex.Message);
            Assert.That(ex.InnerException.Message.StartsWith("The remote name could not be resolved"), "Unexpected inner exception message: " + ex.InnerException.Message);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingUrl))]
        public void HttpSignHashWithInvalidExtendingUrlTest(Ksi ksi)
        {
            Assert.DoesNotThrow(delegate
            {
                SignHash(ksi);
            }, "Invalid exteding url should not prevent signing.");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingPass))]
        public void HttpSignHashWithInvalidExtendingPassTest(Ksi ksi)
        {
            Assert.DoesNotThrow(delegate
            {
                SignHash(ksi);
            }, "Invalid exteding pass should not prevent signing.");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void TcpSignHashTest(Ksi ksi)
        {
            VerificationResult verificationResult = SignHash(ksi);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCasesInvalidPass))]
        public void TcpSignHashInvalidPassTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceException>(delegate
            {
                SignHash(ksi);
            });
            Assert.AreEqual("Server responded with error message. Status: 258; Message: The request could not be authenticated.", ex.Message);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCasesInvalidPort))]
        public void TcpSignHashInvalidPortTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                SignHash(ksi);
            });
            Assert.That(ex.Message.StartsWith("Completing connection failed"), "Unexpected exception message: " + ex.Message);
            Assert.That(ex.InnerException.Message.StartsWith("No connection could be made because the target machine actively refused it"),
                "Unexpected inner exception message: " + ex.InnerException.Message);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void HttpSignedHashVerifyWithInvalidHashTest(Ksi ksi)
        {
            VerificationResult verificationResult = SignedHashVerifyWithInvalidHash(ksi);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode, "Invalid hash should not verify with key based policy");
            Assert.AreEqual(VerificationError.Gen01, verificationResult.VerificationError);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void TcpSignedHashVerifyWithInvalidHashTest(Ksi ksi)
        {
            VerificationResult verificationResult = SignedHashVerifyWithInvalidHash(ksi);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode, "Invalid hash should not verify with key based policy");
            Assert.AreEqual(VerificationError.Gen01, verificationResult.VerificationError);
        }

        private VerificationResult SignHash(Ksi ksi)
        {
            IKsiSignature signature = ksi.Sign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));

            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = new DataHash(HashAlgorithm.Sha2256,
                    Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")),
                PublicationsFile = ksi.GetPublicationsFile()
            };
            KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));
            return policy.Verify(verificationContext);
        }

        public VerificationResult SignedHashVerifyWithInvalidHash(Ksi ksi)
        {
            using (MemoryStream memoryStream = new MemoryStream(Encoding.UTF8.GetBytes("test")))
            {
                IDataHasher dataHasher = CryptoTestFactory.CreateDataHasher(HashAlgorithm.Sha2256);
                dataHasher.AddData(memoryStream);
                IKsiSignature signature = ksi.Sign(dataHasher.GetHash());

                VerificationContext verificationContext = new VerificationContext(signature)
                {
                    DocumentHash = new DataHash(HashAlgorithm.Sha2256,
                        Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")),
                    PublicationsFile = ksi.GetPublicationsFile()
                };
                KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                    CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));

                return policy.Verify(verificationContext);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void ParallelSigningHttpTest(Ksi ksi)
        {
            ParallelSigningTest(ksi);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void ParallelSigningTcpTest(Ksi ksi)
        {
            ParallelSigningTest(ksi);
        }

        public void ParallelSigningTest(Ksi ksi)
        {
            ManualResetEvent waitHandle = new ManualResetEvent(false);
            int doneCount = 0;
            int runCount = 7;
            string errorMessage = null;

            for (int i = 0; i < runCount; i++)
            {
                Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " Start " + i);
                int k = i;
                long start = DateTime.Now.Ticks;

                new Thread(() =>
                {
                    try
                    {
                        Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " Start signing " + k);
                        IKsiSignature signature = ksi.Sign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
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
                        Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + "\t Done! " + k + "\t It took: " + (DateTime.Now.Ticks - start) / 10000 + " ms");
                        doneCount++;

                        if (doneCount == runCount)
                        {
                            waitHandle.Set();
                        }
                    }
                }).Start();
            }

            Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " Waiting ...");

            waitHandle.WaitOne();

            if (errorMessage != null)
            {
                Assert.Fail("ERROR: " + errorMessage);
            }

            Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " All done.");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void HttpSignInvalidPduFormatTest(Ksi ksi)
        {
            KsiService service = GetHttpKsiService(PduVersion.v2);

            // if new aggregator then no exception 
            try
            {
                service.Sign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            }
            catch (Exception ex)
            {
                Assert.That(ex.Message.StartsWith("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Aggregator"),
                    "Unexpected exception message: " + ex.Message);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void HttpSignDefaultPduFormatTest(Ksi ksi)
        {
            KsiService service = GetHttpKsiServiceWithDefaultPduVersion();
            service.Sign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
        }

        [Test]
        public void HttpAsyncSignHashTest()
        {
            byte[] data = Encoding.UTF8.GetBytes("This is my document");
            KsiService service = GetHttpKsiService();

            IDataHasher dataHasher = KsiProvider.CreateDataHasher();
            dataHasher.AddData(data);
            DataHash dataHash = dataHasher.GetHash();

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            IKsiSignature signature = null;
            IAsyncResult asyncResult = null;

            asyncResult = service.BeginSign(dataHash, delegate(IAsyncResult ar)
            {
                try
                {
                    signature = service.EndSign(asyncResult);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, null);

            waitHandle.WaitOne();

            Assert.IsNotNull(signature, "Signature should not be null.");

            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = dataHash
            };

            InternalVerificationPolicy policy = new InternalVerificationPolicy();
            VerificationResult verificationResult = policy.Verify(verificationContext);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with internal policy");
        }

        [Test]
        public void EndSignArgumentNullTest()
        {
            KsiService service = GetHttpKsiService();

            Assert.Throws<ArgumentNullException>(delegate
            {
                service.EndSign(null);
            });
        }

        [Test]
        public void EndSignInvalidArgumentTest()
        {
            KsiService service = GetHttpKsiService();

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndSign(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Invalid asyncResult, could not cast to correct object."), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void TcpSignHashWithReusedSocketsTest()
        {
            TcpKsiServiceProtocol tcp = new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceUrl), Settings.Default.TcpSigningServicePort);
            HttpKsiServiceProtocol http = new HttpKsiServiceProtocol(Settings.Default.HttpSigningServiceUrl, Settings.Default.HttpExtendingServiceUrl,
                Settings.Default.HttpPublicationsFileUrl);

            KsiService service = new KsiService(
                tcp,
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass),
                http,
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass),
                http,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                TestSetup.PduVersion);

            // test signing using tcp
            // signing 3 hashes simultaneously. 3 sockets will be available after that and will be reused when signing an other 3 hashes.

            IAsyncResult ar1 = service.BeginSign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            IAsyncResult ar2 = service.BeginSign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("2f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            IAsyncResult ar3 = service.BeginSign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("3f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);

            Stack<Socket> availableSockets =
                (Stack<Socket>)typeof(TcpKsiServiceProtocol).GetField("_availableSockets", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(tcp);

            Assert.AreEqual(0, availableSockets.Count, "Unexpected amount of available sockets");

            IKsiSignature sig1 = service.EndSign(ar1);
            Assert.AreEqual(1, availableSockets.Count, "Unexpected amount of available sockets");
            IKsiSignature sig2 = service.EndSign(ar2);
            Assert.AreEqual(2, availableSockets.Count, "Unexpected amount of available sockets");
            IKsiSignature sig3 = service.EndSign(ar3);
            Assert.AreEqual(3, availableSockets.Count, "Unexpected amount of available sockets");

            Socket socket1 = availableSockets.ToArray()[0];
            Socket socket2 = availableSockets.ToArray()[1];
            Socket socket3 = availableSockets.ToArray()[2];

            IAsyncResult ar4 = service.BeginSign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("4f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            Assert.AreEqual(2, availableSockets.Count, "Unexpected amount of available sockets");
            IAsyncResult ar5 = service.BeginSign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("5f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            Assert.AreEqual(1, availableSockets.Count, "Unexpected amount of available sockets");
            IAsyncResult ar6 = service.BeginSign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("6f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            Assert.AreEqual(0, availableSockets.Count, "Unexpected amount of available sockets");

            IKsiSignature sig4 = service.EndSign(ar4);
            Assert.AreEqual(1, availableSockets.Count, "Unexpected amount of available sockets");
            IKsiSignature sig5 = service.EndSign(ar5);
            Assert.AreEqual(2, availableSockets.Count, "Unexpected amount of available sockets");
            IKsiSignature sig6 = service.EndSign(ar6);
            Assert.AreEqual(3, availableSockets.Count, "Unexpected amount of available sockets");

            Assert.AreEqual(socket1, availableSockets.ToArray()[2], "Unexpected socket at position 2");
            Assert.AreEqual(socket2, availableSockets.ToArray()[1], "Unexpected socket at position 1");
            Assert.AreEqual(socket3, availableSockets.ToArray()[0], "Unexpected socket at position 0");
        }

        [Test]
        public void TcpSignHashesWithReusingSocketsButTimeoutTest()
        {
            TcpKsiServiceProtocol tcp = new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceUrl), Settings.Default.TcpSigningServicePort, 60000);
            HttpKsiServiceProtocol http = new HttpKsiServiceProtocol(Settings.Default.HttpSigningServiceUrl, Settings.Default.HttpExtendingServiceUrl,
                Settings.Default.HttpPublicationsFileUrl);

            Ksi ksi = new Ksi(new KsiService(
                tcp,
                new ServiceCredentials(Settings.Default.HttpSigningServiceUser, Settings.Default.HttpSigningServicePass),
                http,
                new ServiceCredentials(Settings.Default.HttpExtendingServiceUser, Settings.Default.HttpExtendingServicePass),
                http,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                TestSetup.PduVersion));

            Stack<Socket> availableSockets =
                (Stack<Socket>)typeof(TcpKsiServiceProtocol).GetField("_availableSockets", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(tcp);

            // test signing using tcp
            // time between two signing requests is more than 20 sec and server has closed connections thus sockets cannot be equal
            IKsiSignature s1 = ksi.Sign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            Assert.AreEqual(1, availableSockets.Count, "Unexpected amount of available sockets");
            Socket socket = availableSockets.ToArray()[0];
            Thread.Sleep(25000);
            IKsiSignature s2 = ksi.Sign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            Assert.AreEqual(1, availableSockets.Count, "Unexpected amount of available sockets");
            Assert.AreNotEqual(socket, availableSockets.ToArray()[0], "Unexpected socket at position 0");
        }
    }
}