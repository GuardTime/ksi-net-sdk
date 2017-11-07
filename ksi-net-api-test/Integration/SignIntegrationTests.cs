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
using Guardtime.KSI.Test.Signature.Verification;
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
        public void HttpSignSm3HashTest(Ksi ksi)
        {
            DataHash hash = new DataHash(HashAlgorithm.Sm3, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = ksi.Sign(hash);

            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = hash,
                PublicationsFile = ksi.GetPublicationsFile()
            };
            KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"));
            VerificationResult verificationResult = policy.Verify(verificationContext);
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
            Assert.IsNotNull(ex.InnerException, "Inner exception should not be null");
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
            Assert.IsNotNull(ex.InnerException, "Inner exception should not be null");
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
            DataHash hash = new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = ksi.Sign(hash);

            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = hash,
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

        [Test]
        public void UseDeprecatedHmacAlgoTest()
        {
            KsiService service = GetService(PduVersion.v2, HashAlgorithm.Sha1, HashAlgorithm.Sha2256);
            Ksi ksi = new Ksi(service);

            HashingException ex = Assert.Throws<HashingException>(delegate
            {
                SignHash(ksi);
            });

            Assert.AreEqual("Hash algorithm SHA1 is deprecated since 01.07.2016 and can not be used for HMAC.", ex.Message);
        }

        [Test]
        public void LergacyUseDeprecatedHmacAlgoTest()
        {
            KsiService service = GetService(PduVersion.v1, HashAlgorithm.Sha1, HashAlgorithm.Sha2256);
            Ksi ksi = new Ksi(service);

            HashingException ex = Assert.Throws<HashingException>(delegate
            {
                SignHash(ksi);
            });

            Assert.AreEqual("Hash algorithm SHA1 is deprecated since 01.07.2016 and can not be used for HMAC.", ex.Message);
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
                        ksi.Sign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
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

            object testObject = new object();
            bool isAsyncStateCorrect = false;

            service.BeginSign(dataHash, delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncStateCorrect = ar.AsyncState == testObject;
                    signature = service.EndSign(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            waitHandle.WaitOne();

            Assert.IsNotNull(signature, "Signature should not be null.");
            Assert.AreEqual(true, isAsyncStateCorrect, "Unexpected async state.");

            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = dataHash
            };

            InternalVerificationPolicy policy = new InternalVerificationPolicy();
            VerificationResult verificationResult = policy.Verify(verificationContext);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with internal policy");
        }

        [Test]
        public void HttpAsyncSignWithInvalidPassTest()
        {
            byte[] data = Encoding.UTF8.GetBytes("This is my document");
            KsiService service = GetHttpKsiServiceWithInvalidSigningPass();

            IDataHasher dataHasher = KsiProvider.CreateDataHasher();
            dataHasher.AddData(data);
            DataHash dataHash = dataHasher.GetHash();

            ManualResetEvent waitHandle = new ManualResetEvent(false);
            Exception ex = null;
            IKsiSignature signature = null;

            service.BeginSign(dataHash, delegate(IAsyncResult ar)
            {
                try
                {
                    signature = service.EndSign(ar);
                }
                catch (Exception e)
                {
                    ex = e;
                }
                finally
                {
                    waitHandle.Set();
                }
            }, null);

            waitHandle.WaitOne();

            Assert.IsNull(signature, "Signature should be null.");
            Assert.IsNotNull(ex, "Exception should not be null.");
            Assert.AreEqual("Server responded with error message. Status: 258; Message: The request could not be authenticated.", ex.Message);
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

            Assert.That(ex.Message.StartsWith("Invalid asyncResult type:"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void TcpSignHashWithReusedSocketTest()
        {
            DataHash hash1 = new DataHash(HashAlgorithm.Sha2256, Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            DataHash hash2 = new DataHash(HashAlgorithm.Sha2256, Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            DataHash hash3 = new DataHash(HashAlgorithm.Sha2256, Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            DataHash hash4 = new DataHash(HashAlgorithm.Sha2256, Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));

            TcpKsiServiceProtocol tcp = new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceUrl), Settings.Default.TcpSigningServicePort);
            KsiService service = GetKsiService(tcp);

            IAsyncResult ar1 = service.BeginSign(hash1, null, null);
            IAsyncResult ar2 = service.BeginSign(hash2, null, null);

            IKsiSignature sig1 = service.EndSign(ar1);
            Assert.AreEqual(hash1, sig1.InputHash, "Unexpected signature input hash");
            IKsiSignature sig2 = service.EndSign(ar2);
            Assert.AreEqual(hash2, sig2.InputHash, "Unexpected signature input hash");

            Socket socket1 = GetSocket(tcp);

            IAsyncResult ar3 = service.BeginSign(hash3, null, null);
            IAsyncResult ar4 = service.BeginSign(hash4, null, null);

            IKsiSignature sig3 = service.EndSign(ar3);
            Assert.AreEqual(hash3, sig3.InputHash, "Unexpected signature input hash");
            IKsiSignature sig4 = service.EndSign(ar4);
            Assert.AreEqual(hash4, sig4.InputHash, "Unexpected signature input hash");

            Socket socket2 = GetSocket(tcp);

            Assert.AreEqual(socket1, socket2, "Sockets should be equal");
        }

        [Test]
        public void TcpSignHashesWithSocketReuseAndTimeoutTest()
        {
            DataHash hash1 = new DataHash(HashAlgorithm.Sha2256, Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            DataHash hash2 = new DataHash(HashAlgorithm.Sha2256, Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));

            TcpKsiServiceProtocol tcp = new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceUrl), Settings.Default.TcpSigningServicePort, 30000);
            KsiService service = GetKsiService(tcp);

            IAsyncResult ar1 = service.BeginSign(hash1, null, null);

            IKsiSignature sig1 = service.EndSign(ar1);
            Socket socket1 = GetSocket(tcp);

            Assert.AreEqual(hash1, sig1.InputHash, "Unexpected signature input hash");

            Socket socket2 = GetSocket(tcp);

            Assert.AreEqual(socket1, socket2, "Sockets should be equal");

            // after 20 sec server will close connection
            Thread.Sleep(22000);

            IAsyncResult ar2 = service.BeginSign(hash2, null, null);

            IKsiSignature sig2 = service.EndSign(ar2);
            Assert.AreEqual(hash2, sig2.InputHash, "Unexpected signature input hash");

            socket2 = GetSocket(tcp);

            Assert.AreNotEqual(socket1, socket2, "Sockets should not be equal");
        }

        [Test]
        public void TcpSignHashesWithDisposedServiceProtocolTest()
        {
            TcpKsiServiceProtocol tcp = new TcpKsiServiceProtocol(IPAddress.Parse(Settings.Default.TcpSigningServiceUrl), Settings.Default.TcpSigningServicePort);
            KsiService service = GetKsiService(tcp);

            IAsyncResult ar1 = service.BeginSign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            IAsyncResult ar2 = service.BeginSign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("2f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            service.EndSign(ar1);

            Assert.IsNotNull(GetSocket(tcp), "Socket should not be null");
            tcp.Dispose();

            Assert.IsNull(GetSocket(tcp), "Socket should be null");

            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                service.EndSign(ar2);
            });

            Assert.That(ex.Message.StartsWith("TCP KSI service protocol is disposed."), "Unexpected exception message: " + ex.Message);

            ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                service.BeginSign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("3f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")), null, null);
            });

            Assert.That(ex.Message.StartsWith("TCP KSI service protocol is disposed."), "Unexpected exception message: " + ex.Message);
        }

        private static Socket GetSocket(TcpKsiServiceProtocol tcp)
        {
            return (Socket)typeof(TcpKsiServiceProtocol).GetField("_socket", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(tcp);
        }

        private static KsiService GetKsiService(TcpKsiServiceProtocol tcp)
        {
            HttpKsiServiceProtocol http = new HttpKsiServiceProtocol(Settings.Default.HttpSigningServiceUrl, Settings.Default.HttpExtendingServiceUrl,
                Settings.Default.HttpPublicationsFileUrl);

            KsiService service = new KsiService(
                tcp,
                new ServiceCredentials(Settings.Default.TcpSigningServiceUser, Settings.Default.TcpSigningServicePass,
                    GetHashAlgorithm(Settings.Default.TcpSigningServiceHmacAlgorithm)),
                null,
                null,
                http,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root), CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))),
                new KsiSignatureFactory(new EmptyVerificationPolicy()),
                TestSetup.PduVersion);
            return service;
        }
    }
}