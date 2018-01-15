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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Publication;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class ExtenderResponseCalendarHashChainAlgorithmDeprecatedTests
    {
        [Test]
        public void TestMissingContext()
        {
            ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule rule = new ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule();

            // Argument null exception when no context
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
            Assert.AreEqual("context", ex.ParamName);
        }

        [Test]
        public void TestContextMissingSignature()
        {
            ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule rule = new ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule();

            // Verification exception on missing KSI signature 
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();
                rule.Verify(context);
            });
            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"));
        }

        [Test]
        public void TestOkAlgorithm()
        {
            // Check extender response calendar hash chains that use hash algorithms without deprecated date
            TestSignature(Properties.Resources.KsiSignature_Ok, VerificationResultCode.Ok);
        }

        [Test]
        public void TestOkAlgorithmBeforeDeprecatedDate()
        {
            // Check extender response calendar hash chain that use hash algorithms with deprecated date and publication time is before deprecated date
            TestSignature(Properties.Resources.KsiSignature_Sha1CalendarLeftLinkAlgorithm_2016, VerificationResultCode.Ok);
        }

        [Test]
        public void TestInvalidAlgorithmAfterDeprecatedDate()
        {
            // Check extender response calendar hash chain that use hash algorithms with deprecated date and publication time is after deprecated date
            TestSignature(Properties.Resources.KsiSignature_Sha1CalendarLeftLinkAlgorithm_2017, VerificationResultCode.Na);
        }

        private static void TestSignature(string signaturePath, VerificationResultCode resultCode)
        {
            ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule rule = new ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, signaturePath), FileMode.Open))
            {
                IKsiSignature ksiSignature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream);

                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
                testPublicationsFile.NearestPublications.Add(ksiSignature.AggregationTime,
                    new PublicationRecordInPublicationFile(new RawTag(0x703, false, false,
                        Base16.Decode("3029020455ce349a04210115BA5EB48C064B198A09D37E8C022C281C1CA1E36216EA43E811DF51A7268013"))));

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = ksiSignature,
                    PublicationsFile = testPublicationsFile,
                    ExtendedCalendarHashChain = ksiSignature.CalendarHashChain
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(resultCode, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestPublicationsFileMissingNewerPublicationRecord()
        {
            ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule rule = new ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule();

            // Check no publication found after current signature
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestPublicationsFile testPublicationsFile = new TestPublicationsFile();

                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    PublicationsFile = testPublicationsFile,
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Na, verificationResult.ResultCode);
            }
        }
    }
}