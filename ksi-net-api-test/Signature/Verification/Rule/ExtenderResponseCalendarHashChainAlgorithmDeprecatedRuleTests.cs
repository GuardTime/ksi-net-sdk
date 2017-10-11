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
            Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule rule = new ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();
                rule.Verify(context);
            });
        }

        [Test]
        public void TestOkCalendarAlgorithms()
        {
            // Check extender response calendar hash algorithm
            ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule rule = new ExtenderResponseCalendarHashChainAlgorithmDeprecatedRule();

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
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
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }
    }
}