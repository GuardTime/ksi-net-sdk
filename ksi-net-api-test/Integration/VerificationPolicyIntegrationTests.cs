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

using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Publication;
using NUnit.Framework;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System;

namespace Guardtime.KSI.Test.Integration
{
    [TestFixture]
    public class VerificationPolicyIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetKeyBasedVerificationData))]
        public void KeyBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "KeyBasedVerificationPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetKeyBasedVerificationDataWithNoPublication))]
        public void KeyBasedVerificationTestWithNoPublication(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "KeyBasedVerificationPolicyWithNoPublication");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetPublicationFileBasedVerificationData))]
        public void PublicationFileBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "PublicationFileBasedVerificationPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetPublicationFileBasedVerificationNoExtendingData))]
        public void PublicationFileBasedVerificationNoExtendingTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "PublicationFileBasedVerificationNoExtendingPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetPublicationStringVerificationData))]
        public void PublicationStringBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "PublicationStringBasedVerificationPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetPublicationStringVerificationNoExtendingData))]
        public void PublicationStringBasedVerificationNoExtendingTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "PublicationStringBasedVerificationNoExtendingPolicy");
        }

        [Test]
        public void PublicationStringBasedVerificationUsingOldStringTest()
        {
            DataHolderForIntegrationTests data = new DataHolderForIntegrationTests(
                "resources/signature/integration-test-signatures/ok-sig-extended-2014-05-15.ksig:false:Na: : :UserProvidedPublicationCreationTimeVerificationRule".Split(':'));
            new CommonTestExecution().TestExecution(data, "PublicationStringBasedVerificationUsingOldStringPolicy");
        }

        [Test, TestCaseSource(typeof(CommonGetTestFilesAndResults), nameof(CommonGetTestFilesAndResults.GetCalendarBasedVerificationData))]
        public void CalendarBasedVerificationTest(DataHolderForIntegrationTests data)
        {
            new CommonTestExecution().TestExecution(data, "CalendarBasedVerificationPolicy");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void InternalVerificationAsDefaultVerification(KsiService service)
        {
            InternalVerificationPolicy policy = new InternalVerificationPolicy();
            VerificationContext context = new VerificationContext();
            IKsiSignatureFactory factory = new KsiSignatureFactory(policy);
            Ksi ksi = new Ksi(service, factory);

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.AggregationHashChainMetadataWithoutPaddingFail), FileMode.Open))
            {
                KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
                {
                    IKsiSignature ksiSignature = factory.Create(stream);

                    Console.WriteLine("Must not reach");
                });
                Assert.That(ex.VerificationResult.VerificationError.Equals(VerificationError.Int11), "Unexpected verification error code: " + ex.VerificationResult.VerificationError);
                Console.WriteLine("All OK");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void KeyBasedVerificationAsDefaultVerification(KsiService service)
        {
            KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy(new X509Store(StoreName.Root),
                                CryptoTestFactory.CreateCertificateSubjectRdnSelector(new List<CertificateSubjectRdn>
                                {
                                    new CertificateSubjectRdn("1.2.840.113549.1.9.1", "publications@guardtime.com")
                                }));
            VerificationContext context = new VerificationContext();
            context.PublicationsFile = service.GetPublicationsFile();
            KsiSignatureFactory factory = new KsiSignatureFactory(policy, context);

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.Signature_Wrong_Cert_ID), FileMode.Open))
            {
                KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
                {
                    IKsiSignature ksiSignature = factory.Create(stream);
                    Console.WriteLine("Must not reach");
                });
                Assert.That(ex.VerificationResult.VerificationError.Equals(VerificationError.Key01), "Unexpected verification error code: " + ex.VerificationResult.VerificationError);
                Console.WriteLine("All OK");

            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void CalendarBasedVerificationAsDefaultVerification(KsiService service)
        {
            CalendarBasedVerificationPolicy policy = new CalendarBasedVerificationPolicy();
            VerificationContext context = new VerificationContext();
            context.IsExtendingAllowed = true;
            context.KsiService = service;
            KsiSignatureFactory factory = new KsiSignatureFactory(policy, context);

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.All_Wrong_Chains_Invalid_Signature), FileMode.Open))
            {
                KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
                {
                    IKsiSignature ksiSignature = factory.Create(stream);
                    Console.WriteLine("Must not reach");
                });
                Assert.That(ex.VerificationResult.VerificationError.Equals(VerificationError.Cal02), "Unexpected verification error code: " + ex.VerificationResult.VerificationError);
                Console.WriteLine("All OK");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void PublicationFileBasedVerificationAsDefaultVerification(KsiService service)
        {
            PublicationBasedVerificationPolicy policy = new PublicationBasedVerificationPolicy();
            VerificationContext context = new VerificationContext();
            context.PublicationsFile = service.GetPublicationsFile();
            context.IsExtendingAllowed = true;
            context.KsiService = service;
            KsiSignatureFactory factory = new KsiSignatureFactory(policy, context);

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.All_Wrong_Chains_Invalid_Signature), FileMode.Open))
            {
                KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
                {
                    IKsiSignature ksiSignature = factory.Create(stream);
                    Console.WriteLine("Must not reach");
                });
                Assert.That(ex.VerificationResult.VerificationError.Equals(VerificationError.Pub03), "Unexpected verification error code: " + ex.VerificationResult.VerificationError);
                Console.WriteLine("All OK");
            }
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(KsiServiceTestCases))]
        public void UserPublicationBasedVerificationAsDefaultVerification(KsiService service)
        {
            PublicationBasedVerificationPolicy policy = new PublicationBasedVerificationPolicy();

            VerificationContext context = new VerificationContext();
            context.UserPublication = new PublicationData("AAAAAA-CW45II-AAKWRK-F7FBNM-KB6FNV-DYYFW7-PJQN6F-JKZWBQ-3OQYZO-HCB7RA-YNYAGA-ODRL2V");
            context.IsExtendingAllowed = true;
            context.KsiService = service;
            KsiSignatureFactory factory = new KsiSignatureFactory(policy, context);

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.All_Wrong_Chains_Invalid_Signature), FileMode.Open))
            {
                KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
                {
                    IKsiSignature ksiSignature = factory.Create(stream);
                    Console.WriteLine("Must not reach");
                });
                Assert.That(ex.VerificationResult.VerificationError.Equals(VerificationError.Pub03), "Unexpected verification error code: " + ex.VerificationResult.VerificationError);
                Console.WriteLine("All OK");
            }
        }
    }
}