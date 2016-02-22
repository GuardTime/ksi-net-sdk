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

using System.IO;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using NUnit.Framework;

namespace Guardtime.KSI.Integration
{
    [TestFixture]
    public class ExtendIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void ExtendToHeadAndVerifyUserProvidedPublicationTest(Ksi ksi)
        {
            UserProvidedPublicationVerificationRule rule = new UserProvidedPublicationVerificationRule();

            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                PublicationData publicationData = ksi.GetPublicationsFile().GetLatestPublication().PublicationData;

                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedSignature = ksi.ExtendToHead(ksiSignature);

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

            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
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

            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
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
            using (FileStream signatureToExtend = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open),
                              signatureToGetPubRecord = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Extended, FileMode.Open))
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
            UserProvidedPublicationVerificationRule rule = new UserProvidedPublicationVerificationRule();

            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                IKsiSignature ksiSignature = new KsiSignatureFactory().Create(stream);
                IKsiSignature extendedToLatest = ksi.Extend(ksiSignature, ksi.GetPublicationsFile().GetLatestPublication());
                IKsiSignature extendedToNearest = ksi.Extend(ksiSignature);

                Assert.True(extendedToLatest.PublicationRecord.PublicationData.PublicationTime > extendedToNearest.PublicationRecord.PublicationData.PublicationTime);
                Assert.AreEqual(extendedToNearest.PublicationRecord.PublicationData.PublicationTime, 1408060800);
            }
        }
    }
}