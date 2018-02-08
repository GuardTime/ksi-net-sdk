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
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Service.Tcp;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using NUnit.Framework;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Test.Properties;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class ExtendIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiListWithInvalidExtendingPass))]
        public void ExtendInvalidPassTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(TestUtil.GetSignature());
            });

            Assert.AreEqual("Server responded with error message. Status: 258; Message: Failed hmac check.", ex.Message);
        }

        /// <summary>
        /// Test extending while signing service pass is invalid which should not prevent extending.
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiListWithInvalidSigningPass))]
        public void ExtendSuccessWithInvalidSigningPassTest(Ksi ksi)
        {
            Assert.DoesNotThrow(delegate
            {
                ksi.Extend(TestUtil.GetSignature());
            }, "Invalid signing pass should not prevent extending.");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void ExtendAndVerifyTest(Ksi ksi)
        {
            PublicationBasedVerificationPolicy policy = new PublicationBasedVerificationPolicy();

            IKsiSignature ksiSignature = TestUtil.GetSignature();
            IKsiSignature extendedSignature = ksi.Extend(ksiSignature);
            PublicationData publicationData = ksi.GetPublicationsFile().GetNearestPublicationRecord(ksiSignature.AggregationTime).PublicationData;

            VerificationContext context = new VerificationContext(extendedSignature)
            {
                UserPublication = publicationData,
                KsiService = GetHttpKsiService()
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void ExtendAndVerifySignatureWithAggregationChainsOnly(Ksi ksi)
        {
            PublicationBasedVerificationPolicy rule = new PublicationBasedVerificationPolicy();

            // signature contains only aggregation chains
            IKsiSignature ksiSignature = TestUtil.GetSignature(Resources.KsiSignature_Ok_Only_Aggregtion_Chains);
            IKsiSignature extendedSignature = ksi.Extend(ksiSignature);
            PublicationData publicationData = ksi.GetPublicationsFile().GetNearestPublicationRecord(ksiSignature.AggregationTime).PublicationData;

            VerificationContext context = new VerificationContext(extendedSignature)
            {
                UserPublication = publicationData
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void ExtendInvalidSignatureTest(Ksi ksi)
        {
            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Extend(TestUtil.GetSignature(Resources.KsiSignature_Invalid_Aggregation_Chain_Input_Hash));
            });

            Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.Signature);
            Assert.IsTrue(ex.Signature.IsExtended);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void ExtendAndVerifyToUserProvidedPublicationTest(Ksi ksi)
        {
            PublicationBasedVerificationPolicy rule = new PublicationBasedVerificationPolicy();
            PublicationData publicationData = new PublicationData("AAAAAA-CW45II-AAKWRK-F7FBNM-KB6FNV-DYYFW7-PJQN6F-JKZWBQ-3OQYZO-HCB7RA-YNYAGA-ODRL2V");
            IKsiSignature extendedSignature = ksi.Extend(TestUtil.GetSignature(), publicationData);

            VerificationContext context = new VerificationContext(extendedSignature)
            {
                UserPublication = publicationData
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void ExtendAndVerifyToUserProvidedPublicationNotInPublicationsFileTest(Ksi ksi)
        {
            PublicationBasedVerificationPolicy rule = new PublicationBasedVerificationPolicy();
            // publication data that is not included in publications file. Time: 2016-07-12 00:00:00 UTC
            PublicationData publicationData = new PublicationData("AAAAAA-CXQQZQ-AAPGJF-HGNMUN-DXEIQW-NJZZOE-J76OK4-BV3FKY-AEAWIP-KSPZPW-EJKVAI-JPOOR7");
            IKsiSignature extendedSignature = ksi.Extend(TestUtil.GetSignature(), publicationData);

            VerificationContext context = new VerificationContext(extendedSignature)
            {
                UserPublication = publicationData
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void InvalidExtendAndVerifyToUserProvidedPublicationFromTestCoreTest(Ksi ksi)
        {
            // publication data from Test core, not included in publications file. Time: 2016-07-12 00:00:00 UTC
            PublicationData publicationData = new PublicationData("AAAAAA-CXQQZQ-AAOSZH-ONCB4K-TFGPBW-R6S6TF-6EW4DU-4QMP7X-GI2VCO-TNGAZM-EV6AZR-464IOA");
            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Extend(TestUtil.GetSignature(), publicationData);
            });

            Assert.AreEqual(VerificationError.Int09.Code, ex.VerificationResult.VerificationError.Code, "Invalid result code");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsiService))]
        public void InvalidExtendToUserProvidedPublicationFromTestCoreAllowExtendingTest(KsiService service)
        {
            PublicationBasedVerificationPolicy rule = new PublicationBasedVerificationPolicy();
            // publication data from Test core. not included in publications file. Time: 2016-07-12 00:00:00 UTC
            PublicationData publicationData = new PublicationData("AAAAAA-CXQQZQ-AAOSZH-ONCB4K-TFGPBW-R6S6TF-6EW4DU-4QMP7X-GI2VCO-TNGAZM-EV6AZR-464IOA");
            VerificationContext context = new VerificationContext(TestUtil.GetSignature())
            {
                IsExtendingAllowed = true,
                UserPublication = publicationData,
                KsiService = service
            };

            VerificationResult verificationResult = rule.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
            Assert.AreEqual(VerificationError.Pub01, verificationResult.VerificationError);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void InvalidExtendToUserProvidedPublicationTest(Ksi ksi)
        {
            // publication data with modified hash
            PublicationData publicationData = new PublicationData("AAAAAA-CW45II-AAIYPA-UJ4GRT-HXMFBE-OTB4AB-XH3PT3-KNIKGV-PYCJXU-HL2TN4-RG6SCA-ZP3ZLX");
            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Extend(TestUtil.GetSignature(), publicationData);
            });

            Assert.AreEqual(VerificationError.Int09.Code, ex.VerificationResult.VerificationError.Code, "Unexpected result code");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void ExtendToOtherExtendedSignatureAndVerifyWithUserProvidedPublication(Ksi ksi)
        {
            IKsiSignature ksiSignatureToExtend = TestUtil.GetSignature();
            IKsiSignature ksiSignatureForPublicationRecord = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended);
            IKsiSignature extendedSignature = ksi.Extend(ksiSignatureToExtend, ksiSignatureForPublicationRecord.PublicationRecord);

            Assert.AreEqual(ksiSignatureForPublicationRecord.PublicationRecord.PublicationData.PublicationHash,
                extendedSignature.PublicationRecord.PublicationData.PublicationHash);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void ExtendToNearestPublicationTest(Ksi ksi)
        {
            IKsiSignature ksiSignature = TestUtil.GetSignature();
            IKsiSignature extendedToLatest = ksi.Extend(ksiSignature, ksi.GetPublicationsFile().GetLatestPublication());
            IKsiSignature extendedToNearest = ksi.Extend(ksiSignature);

            Assert.True(extendedToLatest.PublicationRecord.PublicationData.PublicationTime > extendedToNearest.PublicationRecord.PublicationData.PublicationTime);
            Assert.AreEqual(1455494400, extendedToNearest.PublicationRecord.PublicationData.PublicationTime);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiList))]
        public void ParallelExtendingTest(Ksi ksi)
        {
            ManualResetEvent waitHandle = new ManualResetEvent(false);
            int doneCount = 0;
            int runCount = 10;
            string errorMessage = null;
            MemoryStream ms = new MemoryStream();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok), FileMode.Open))
            {
                stream.CopyTo(ms);
            }

            for (int i = 0; i < runCount; i ++)
            {
                Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " Start " + i);
                int k = i;

                MemoryStream s = new MemoryStream();
                ms.Seek(0, SeekOrigin.Begin);
                ms.CopyTo(s);
                s.Seek(0, SeekOrigin.Begin);

                Task.Run(() =>
                {
                    long start = DateTime.Now.Ticks;
                    Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " Start extending " + k);
                    try
                    {
                        IKsiSignature ksiSignature = new KsiSignatureFactory().Create(s);
                        IKsiSignature extendedToNearest = ksi.Extend(ksiSignature);
                        s.Close();

                        Assert.AreEqual(1455494400, extendedToNearest.PublicationRecord.PublicationData.PublicationTime);
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
                });
            }

            Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " Waiting ...");

            waitHandle.WaitOne(20000);

            if (errorMessage != null)
            {
                Assert.Fail("ERROR: " + errorMessage);
            }

            Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " All done.");
        }

        [Test]
        public void ExtendInvalidPduFormatTest()
        {
            KsiService service = GetHttpKsiService(PduVersion.v2);

            try
            {
                service.Extend(1455494400);
            }
                // if new aggregator then no exception
            catch (Exception ex)
            {
                Assert.That(ex.Message.StartsWith("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Extender"),
                    "Unexpected exception message: " + ex.Message);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServices))]
        public void AsyncExtendTest(KsiService service)
        {
            ManualResetEvent waitHandle = new ManualResetEvent(false);
            CalendarHashChain cal = null;

            object testObject = new object();
            bool isAsyncCorrect = false;

            service.BeginExtend(1455400000, delegate(IAsyncResult ar)
            {
                try
                {
                    isAsyncCorrect = ar.AsyncState == testObject;
                    cal = service.EndExtend(ar);
                }
                finally
                {
                    waitHandle.Set();
                }
            }, testObject);

            waitHandle.WaitOne(10000);

            Assert.IsNotNull(cal, "Calendar hash chain should not be null.");
            Assert.AreEqual(true, isAsyncCorrect, "Unexpected async state.");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServicesWithInvalidExtendingPass))]
        public void AsyncExtendWithInvalidPassTest(KsiService service)
        {
            ManualResetEvent waitHandle = new ManualResetEvent(false);
            Exception ex = null;
            CalendarHashChain cal = null;

            service.BeginExtend(1455400000, delegate(IAsyncResult ar)
            {
                try
                {
                    cal = service.EndExtend(ar);
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

            waitHandle.WaitOne(10000);

            Assert.IsNull(cal, "Calendar hash chain should be null.");
            Assert.IsNotNull(ex, "Exception should not be null.");
            Assert.AreEqual("Server responded with error message. Status: 258; Message: Failed hmac check.", ex.Message);
        }

        [Test]
        public void HttpExtendMissingUrlTest()
        {
            Ksi ksi = new Ksi(GetHttpKsiServiceWithoutExtendingUrl());

            Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                ksi.Extend(TestUtil.GetSignature());
            });

            Assert.That(ex.Message.StartsWith("Service url is missing"), "Unexpected exception message: " + ex.Message);
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsiWithInvalidExtendingUrl))]
        public void HttpExtendInvalidUrlTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                ksi.Extend(TestUtil.GetSignature());
            });

            Assert.That(ex.Message.StartsWith("Request failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.InnerException, "Inner exception should not be null");
            Assert.That(ex.InnerException.Message.StartsWith("The remote name could not be resolved"), "Unexpected inner exception message: " + ex.InnerException.Message);
        }

        /// <summary>
        /// Test extending via HTTP while signing service url is invalid which should not prevent extending.
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpKsiWithInvalidSigningUrl))]
        public void HttpExtendSuccessWithInvalidSigningUrlTest(Ksi ksi)
        {
            Assert.DoesNotThrow(delegate
            {
                ksi.Extend(TestUtil.GetSignature());
            }, "Invalid signing url should not prevent extending.");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpKsiWithInvalidExtendingPort))]
        public void TcpExtendWithInvalidPortTest(Ksi ksi)
        {
            Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                ksi.Extend(TestUtil.GetSignature());
            });
            Assert.That(ex.Message.StartsWith("Completing connection failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.InnerException, "Inner exception should not be null");
            Assert.That(ex.InnerException.Message.StartsWith("No connection could be made because the target machine actively refused it"),
                "Unexpected inner exception message: " + ex.InnerException.Message);
        }

        /// <summary>
        /// Test extending via TCP while signing service port is invalid which should not prevent extending.
        /// </summary>
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpKsiWithInvalidSigningPort))]
        public void TcpExtendSuccessWithInvalidSigningPortTest(Ksi ksi)
        {
            Assert.DoesNotThrow(delegate
            {
                ksi.Extend(TestUtil.GetSignature());
            }, "Invalid signing port should not prevent extending.");
        }

        [Test]
        public void TcpExtendWithReusedSocketTest()
        {
            KsiService service = GetTcpKsiService();
            ulong aggregationTime = 1455478441;

            IAsyncResult ar1 = service.BeginExtend(aggregationTime, null, null);
            IAsyncResult ar2 = service.BeginExtend(aggregationTime, null, null);

            CalendarHashChain cal1 = service.EndExtend(ar1);
            Assert.AreEqual(aggregationTime, cal1.AggregationTime, "Unexpected calendar aggregation time");
            CalendarHashChain cal2 = service.EndExtend(ar2);
            Assert.AreEqual(aggregationTime, cal2.AggregationTime, "Unexpected calendar aggregation time");

            Socket socket1 = GetExtendingSocket(service);

            IAsyncResult ar3 = service.BeginExtend(aggregationTime, null, null);
            IAsyncResult ar4 = service.BeginExtend(aggregationTime, null, null);

            CalendarHashChain cal3 = service.EndExtend(ar3);
            Assert.AreEqual(aggregationTime, cal3.AggregationTime, "Unexpected calendar aggregation time");
            CalendarHashChain cal4 = service.EndExtend(ar4);
            Assert.AreEqual(aggregationTime, cal4.AggregationTime, "Unexpected calendar aggregation time");

            Socket socket2 = GetExtendingSocket(service);

            Assert.AreEqual(socket1, socket2, "Sockets should be equal");
        }

        [Test]
        public void TcpExtendesWithSocketReuseAndTimeoutTest()
        {
            KsiService service = GetTcpKsiService();
            ulong aggregationTime = 1455478441;

            IAsyncResult ar1 = service.BeginExtend(aggregationTime, null, null);

            CalendarHashChain cal1 = service.EndExtend(ar1);
            Socket socket1 = GetExtendingSocket(service);

            Assert.AreEqual(aggregationTime, cal1.AggregationTime, "Unexpected calendar aggregation time");

            Socket socket2 = GetExtendingSocket(service);

            Assert.AreEqual(socket1, socket2, "Sockets should be equal");

            // after 20 sec server will close connection
            Thread.Sleep(23000);

            IAsyncResult ar2 = service.BeginExtend(aggregationTime, null, null);

            CalendarHashChain cal2 = service.EndExtend(ar2);
            Assert.AreEqual(aggregationTime, cal2.AggregationTime, "Unexpected calendar aggregation time");

            socket2 = GetExtendingSocket(service);

            Assert.AreNotEqual(socket1, socket2, "Sockets should not be equal");
        }

        [Test]
        public void TcpExtendesWithDisposedServiceProtocolTest()
        {
            KsiService service = GetTcpKsiService();
            ulong aggregationTime = 1455478441;

            IAsyncResult ar1 = service.BeginExtend(aggregationTime, null, null);
            IAsyncResult ar2 = service.BeginExtend(aggregationTime, null, null);
            service.EndExtend(ar1);

            TcpKsiExtendingServiceProtocol tcp = GetTcpProtocol(service);

            Assert.IsNotNull(GetExtendingSocket(tcp), "Socket should not be null");
            tcp.Dispose();

            Assert.IsNull(GetExtendingSocket(tcp), "Socket should be null");

            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                service.EndExtend(ar2);
            });

            Assert.That(ex.Message.StartsWith("TCP KSI service protocol is disposed."), "Unexpected exception message: " + ex.Message);

            ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                service.BeginExtend(aggregationTime, null, null);
            });

            Assert.That(ex.Message.StartsWith("TCP KSI service protocol is disposed."), "Unexpected exception message: " + ex.Message);
        }

        private static TcpKsiExtendingServiceProtocol GetTcpProtocol(KsiService service)
        {
            string fieldName = "_extendingServiceProtocol";
            FieldInfo memberInfo = typeof(KsiService).GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
            if (memberInfo != null)
            {
                return (TcpKsiExtendingServiceProtocol)memberInfo.GetValue(service);
            }
            throw new Exception("Could not get field info: " + fieldName);
        }

        private static Socket GetExtendingSocket(KsiService service)
        {
            return GetExtendingSocket(GetTcpProtocol(service));
        }

        private static Socket GetExtendingSocket(TcpKsiExtendingServiceProtocol tcp)
        {
            string fieldName = "_socket";
            FieldInfo memberInfo = typeof(TcpKsiServiceProtocolBase).GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
            if (memberInfo != null)
            {
                return (Socket)memberInfo.GetValue(tcp);
            }
            throw new Exception("Could not get field info: " + fieldName);
        }

        [Test]
        public void UseDeprecatedHmacAlgoTest()
        {
            KsiService service = GetService(PduVersion.v2, HashAlgorithm.Sha2256, HashAlgorithm.Sha1);

            HashingException ex = Assert.Throws<HashingException>(delegate
            {
                service.Extend(1510056000L);
            });
            Assert.That(ex.Message.StartsWith("Hash algorithm SHA1 is deprecated since 2016-07-01 and can not be used for HMAC"),
                "Unexpected inner exception message: " + ex.Message);
        }

        [Test]
        public void LergacyUseDeprecatedHmacAlgoTest()
        {
            KsiService service = GetService(PduVersion.v1, HashAlgorithm.Sha2256, HashAlgorithm.Sha1);

            HashingException ex = Assert.Throws<HashingException>(delegate
            {
                service.Extend(1510056000L);
            });

            Assert.That(ex.Message.StartsWith("Hash algorithm SHA1 is deprecated since 2016-07-01 and can not be used for HMAC"),
                "Unexpected inner exception message: " + ex.Message);
        }
    }
}