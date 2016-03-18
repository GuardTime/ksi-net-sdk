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
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Signature.Verification.Rule;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class ExtendIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingPass))]
        public void ExtendInvalidPassTest(Ksi ksi)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);

                Exception ex = Assert.Throws<KsiException>(delegate
                {
                    ksi.Extend(ksiSignature);
                });

                Assert.AreEqual("Error occured during extending: The request could not be authenticated.", ex.Message);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidExtendingUrl))]
        public void ExtendInvalidUrlTest(Ksi ksi)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);

                Exception ex = Assert.Throws<KsiServiceProtocolException>(delegate
                {
                    ksi.Extend(ksiSignature);
                });

                Assert.That(ex.Message.StartsWith("Request failed"), "Unexpected exception message: " + ex.Message);
                Assert.That(ex.InnerException.Message.StartsWith("The remote name could not be resolved"), "Unexpected inner exception message: " + ex.InnerException.Message);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidSigningUrl))]
        public void ExtendSuccessWithInvalidSigningUrlTest(Ksi ksi)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);

                Assert.DoesNotThrow(delegate
                {
                    ksi.Extend(ksiSignature);
                }, "Invalid signing url should not prevent extending.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidSigningPass))]
        public void ExtendSuccessWithInvalidSigningPassTest(Ksi ksi)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);

                Assert.DoesNotThrow(delegate
                {
                    ksi.Extend(ksiSignature);
                }, "Invalid signing pass should not prevent extending.");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void ExtendAndVerifyTest(Ksi ksi)
        {
            UserProvidedPublicationVerificationRule rule = new UserProvidedPublicationVerificationRule();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedSignature = ksi.Extend(ksiSignature);
                PublicationData publicationData = ksi.GetPublicationsFile().GetNearestPublicationRecord(ksiSignature.AggregationTime).PublicationData;

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = extendedSignature,
                    UserPublication = publicationData
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void ExtendAndVerifyToUserProvidedPublicationTest(Ksi ksi)
        {
            UserProvidedPublicationVerificationRule rule = new UserProvidedPublicationVerificationRule();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                PublicationData publicationData = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K");

                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedSignature = ksi.Extend(ksiSignature, publicationData);

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = extendedSignature,
                    UserPublication = publicationData
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void InvalidExtendToUserProvidedPublicationTest(Ksi ksi)
        {
            UserProvidedPublicationVerificationRule rule = new UserProvidedPublicationVerificationRule();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                // publication data with modified hash
                PublicationData publicationData = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUBD7-OE44VA");

                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedSignature = ksi.Extend(ksiSignature, publicationData);

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = extendedSignature,
                    UserPublication = publicationData
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void ExtendToOtherExtendedSignatureAndVerifyWithUserProvidedPublication(Ksi ksi)
        {
            using (FileStream signatureToExtend = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open),
                              signatureToGetPubRecord = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok_Extended), FileMode.Open))
            {
                IKsiSignature ksiSignatureToExtend = new KsiSignatureFactory().Create(signatureToExtend);
                IKsiSignature ksiSignatureForPublicationRecord = new KsiSignatureFactory().Create(signatureToGetPubRecord);
                IKsiSignature extendedSignature = ksi.Extend(ksiSignatureToExtend, ksiSignatureForPublicationRecord.PublicationRecord);

                Assert.AreEqual(ksiSignatureForPublicationRecord.PublicationRecord.PublicationData.PublicationHash,
                    extendedSignature.PublicationRecord.PublicationData.PublicationHash);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void ExtendToNearestPublicationTest(Ksi ksi)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedToLatest = ksi.Extend(ksiSignature, ksi.GetPublicationsFile().GetLatestPublication());
                IKsiSignature extendedToNearest = ksi.Extend(ksiSignature);

                Assert.True(extendedToLatest.PublicationRecord.PublicationData.PublicationTime > extendedToNearest.PublicationRecord.PublicationData.PublicationTime);
                Assert.AreEqual(extendedToNearest.PublicationRecord.PublicationData.PublicationTime, 1408060800);
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void ParallelExtendingTest(Ksi ksi)
        {
            ManualResetEvent waitHandle = new ManualResetEvent(false);
            int doneCount = 0;
            int runCount = 10;
            string errorMessage = null;

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedToNearest = ksi.Extend(ksiSignature);
            }

            for (int i = 0; i < runCount; i ++)
            {
                Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " Start " + i);
                int k = i;

                MemoryStream s = new MemoryStream();
                using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignatureDo_Ok), FileMode.Open))
                {
                    stream.CopyTo(s);
                }

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

                        Assert.AreEqual(extendedToNearest.PublicationRecord.PublicationData.PublicationTime, 1408060800);
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

            waitHandle.WaitOne();

            if (errorMessage != null)
            {
                Assert.Fail("ERROR: " + errorMessage);
            }

            Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " All done.");
        }
    }
}