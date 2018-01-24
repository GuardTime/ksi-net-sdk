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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Service;
using Guardtime.KSI.Test.Trust;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Policy
{
    [TestFixture]
    public class DefaultVerificationPolicyTests : StaticServiceTestsBase
    {
        private DefaultVerificationPolicy Policy => new DefaultVerificationPolicy();

        [Test]
        public void VerifyWithoutSignatureInContext()
        {
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                // no signature in context
                VerificationContext context = new VerificationContext();
                Policy.Verify(context);
            });

            Assert.That(ex.Message, Does.StartWith("Invalid KSI signature in context: null"));
        }

        [Test]
        public void VerifyWithSignatureNull1()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // signature is null
                Policy.Verify(null,
                    new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                    TestUtil.GetPublicationsFile());
            });

            Assert.AreEqual("ksiSignature", ex.ParamName);
        }

        [Test]
        public void VerifyWithSignatureNull2()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // signature is null
                Policy.Verify(null,
                    new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                    GetStaticKsiService(new byte[] { }));
            });

            Assert.AreEqual("ksiSignature", ex.ParamName);
        }

        [Test]
        public void VerifyWithoutPublicationsInContext()
        {
            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                // no publications file in context
                Policy.Verify(new VerificationContext()
                {
                    Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended),
                });
            });

            Assert.That(ex.Message, Does.StartWith("Invalid publications file in context: null"));
        }

        [Test]
        public void VerifyWithPublicationsFileNull()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // publications file is null
                Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended),
                    new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                    (IPublicationsFile)null);
            });

            Assert.AreEqual("publicationsFile", ex.ParamName);
        }

        [Test]
        public void VerifyWithKsiServiceNull()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // ksi service is null
                Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended),
                    new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                    (IKsiService)null);
            });

            Assert.AreEqual("ksiService", ex.ParamName);
        }

        /// <summary>
        /// Signature is verified with publications file. Method Verify with context is used.
        /// </summary>
        [Test]
        public void VerifyWithPublicationsFile1()
        {
            VerificationContext context = new VerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended),
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                PublicationsFile = TestUtil.GetPublicationsFile()
            };

            VerificationResult result = Policy.Verify(context);
            CheckResult(result, VerificationResultCode.Ok, null, 1, typeof(PublicationBasedVerificationPolicy));
        }

        /// <summary>
        /// Signature is verified with publications file. Method Verify with publications file is used.
        /// </summary>
        [Test]
        public void VerifyWithPublicationsFile2()
        {
            VerificationResult result = Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended),
                new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                TestUtil.GetPublicationsFile());

            CheckResult(result, VerificationResultCode.Ok, null, 1, typeof(PublicationBasedVerificationPolicy));
        }

        /// <summary>
        /// Signature is verified with publications file. Method Verify with publications file is used. Document hash is null.
        /// </summary>
        [Test]
        public void VerifyWithPublicationsFileWithoutDataHash()
        {
            VerificationResult result = Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended),
                null,
                TestUtil.GetPublicationsFile());

            CheckResult(result, VerificationResultCode.Ok, null, 1, typeof(PublicationBasedVerificationPolicy));
        }

        /// <summary>
        /// Signature is verified with publications file, but document hash is invalid. Method Verify with publications file is used.
        /// </summary>
        [Test]
        public void VerifyWithPublicationsFileInvalidDocumentHash()
        {
            VerificationResult result = Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok_Extended),
                // invalid document hash
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                TestUtil.GetPublicationsFile());

            CheckResult(result, VerificationResultCode.Fail, VerificationError.Gen01, 1, typeof(PublicationBasedVerificationPolicy));
        }

        /// <summary>
        /// Signature is verified with key based policy. Method Verify with context is used.
        /// </summary>
        [Test]
        public void VerifyWithKey1()
        {
            VerificationContext context = new VerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                PublicationsFile = TestUtil.GetPublicationsFile()
            };

            VerificationResult result = Policy.Verify(context);
            CheckResult(result, VerificationResultCode.Ok, null, 2, typeof(KeyBasedVerificationPolicy));
        }

        /// <summary>
        /// Signature is verified with key based policy. Method Verify with publications file is used.
        /// </summary>
        [Test]
        public void VerifyWithKey2()
        {
            VerificationResult result = Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok),
                new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                TestUtil.GetPublicationsFile());

            CheckResult(result, VerificationResultCode.Ok, null, 2, typeof(KeyBasedVerificationPolicy));
        }

        /// <summary>
        /// Signature verifies against publications file after automatic extending. Method Verify with context is used.
        /// </summary>
        [Test]
        public void VerifyWithExtendingAndPublicationsFile1()
        {
            VerificationContext context = new VerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok),
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                PublicationsFile = TestUtil.GetPublicationsFile(),
                KsiService = GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455),
                IsExtendingAllowed = true
            };

            VerificationResult result = Policy.Verify(context);
            CheckResult(result, VerificationResultCode.Ok, null, 1, typeof(PublicationBasedVerificationPolicy));
        }

        /// <summary>
        /// Signature verifies against publications file after automatic extending. Method Verify with KSI service is used.
        /// </summary>
        [Test]
        public void VerifyWithExtendingAndPublicationsFile2()
        {
            VerificationResult result = Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok),
                new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455));

            CheckResult(result, VerificationResultCode.Ok, null, 1, typeof(PublicationBasedVerificationPolicy));
        }

        /// <summary>
        /// Not extended signature is verified with key based policy because publications file does not containt suitable publication. 
        /// </summary>
        [Test]
        public void VerifyWithExtendingAndKey()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                PublicationsFileBytes = File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile_201712))
            };

            TestKsiService staticKsiService = new TestKsiService(
                null,
                null,
                protocol,
                new ServiceCredentials(TestConstants.ServiceUser, TestConstants.ServicePass),
                protocol,
                new PublicationsFileFactory(new TestPkiTrustProvider()),
                1043101455,
                PduVersion.v2);

            VerificationResult result = Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok_20171219), null, staticKsiService);
            CheckResult(result, VerificationResultCode.Ok, null, 2, typeof(KeyBasedVerificationPolicy));
        }

        /// <summary>
        /// Signature verifies against publications file after automatic extending. Method Verify with KSI service is used. Document hash is null.
        /// </summary>
        [Test]
        public void VerifyWithExtendingAndPublicationsFileWithoutDataHash()
        {
            VerificationResult result = Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok),
                null,
                GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455));

            CheckResult(result, VerificationResultCode.Ok, null, 1, typeof(PublicationBasedVerificationPolicy));
        }

        /// <summary>
        /// Invalid document hash. Method Verify with KSI service is used.
        /// </summary>
        [Test]
        public void VerifyUsingKsiServiceInvalidDocumentHash()
        {
            VerificationResult result = Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok),
                // invalid document hash
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455));

            CheckResult(result, VerificationResultCode.Fail, VerificationError.Gen01, 1, typeof(PublicationBasedVerificationPolicy));
        }

        /// <summary>
        /// Signature not verified. Calendar auth record signature certificate was not valid at aggregation time.
        /// </summary>
        [Test]
        public void VerifyWithNotValidCertAtAggregationTime()
        {
            VerificationContext context = new VerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Not_Valid_Cert),
                PublicationsFile = TestUtil.GetPublicationsFile()
            };

            VerificationResult result = Policy.Verify(context);
            CheckResult(result, VerificationResultCode.Fail, VerificationError.Key03, 2, typeof(KeyBasedVerificationPolicy));
        }

        [Test]
        public void VerifySignatureWithAggregationChainsOnly()
        {
            VerificationResult result = Policy.Verify(TestUtil.GetSignature(Resources.KsiSignature_Ok_Only_Aggregtion_Chains), null, TestUtil.GetPublicationsFile());
            CheckResult(result, VerificationResultCode.Na, VerificationError.Gen02, 2, typeof(KeyBasedVerificationPolicy));
        }

        private void CheckResult(VerificationResult result, VerificationResultCode expectedResultCode, VerificationError excpectedError, uint expectedChildResultCount,
                                 Type expectedLastChildResultType)
        {
            Assert.AreEqual(expectedResultCode, result.ResultCode, "Unexpected verification result code.");
            if (expectedResultCode != VerificationResultCode.Ok)
            {
                Assert.AreEqual(excpectedError, result.VerificationError, "Unexpected verification error");
            }
            Assert.AreEqual(expectedChildResultCount, result.ChildResults.Count, "Unexpected child result count.");
            Assert.AreEqual(expectedLastChildResultType.Name, result.ChildResults[result.ChildResults.Count - 1].RuleName, "Unexpected last child result rule.");
        }
    }
}