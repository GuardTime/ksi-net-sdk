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
using Guardtime.KSI.Signature;
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
        [Test]
        public void VerifyWithoutSignatureInContext()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                // no signature in context
                VerificationContext context = new VerificationContext();
                policy.Verify(context);
            });

            Assert.That(ex.Message, Does.StartWith("Invalid signature in context: null"));
        }

        [Test]
        public void VerifyWithSignatureNull1()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // signature is null
                policy.Verify(null,
                    new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                    GetPublicationsFile());
            });

            Assert.AreEqual("ksiSignature", ex.ParamName);
        }

        [Test]
        public void VerifyWithSignatureNull2()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // signature is null
                policy.Verify(null,
                    new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                    GetStaticKsiService(new byte[] { }));
            });

            Assert.AreEqual("ksiSignature", ex.ParamName);
        }

        [Test]
        public void VerifyWithDocumentHashNull1()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // document hash is null
                policy.Verify(GetSignature(Resources.KsiSignature_Ok_Extended),
                    null,
                    GetPublicationsFile());
            });

            Assert.AreEqual("documentHash", ex.ParamName);
        }

        [Test]
        public void VerifyWithDocumentHashNull2()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // document hash is null
                policy.Verify(GetSignature(Resources.KsiSignature_Ok_Extended),
                    null,
                    GetStaticKsiService(new byte[] { }));
            });

            Assert.AreEqual("documentHash", ex.ParamName);
        }

        [Test]
        public void VerifyWithoutPublicationsInContext()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();
            VerificationContext context = new VerificationContext()
            {
                Signature = GetSignature(Resources.KsiSignature_Ok_Extended),
            };

            KsiVerificationException ex = Assert.Throws<KsiVerificationException>(delegate
            {
                // no publications file in context
                policy.Verify(context);
            });

            Assert.That(ex.Message, Does.StartWith("Invalid publications file in context: null"));
        }

        [Test]
        public void VerifyWithPublicationsFileNull()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // publications file is null
                policy.Verify(GetSignature(Resources.KsiSignature_Ok_Extended),
                    new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                    (IPublicationsFile)null);
            });

            Assert.AreEqual("publicationsFile", ex.ParamName);
        }

        [Test]
        public void VerifyWithKsiServiceNull()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                // ksi service is null
                policy.Verify(GetSignature(Resources.KsiSignature_Ok_Extended),
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
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();
            VerificationContext context = new VerificationContext()
            {
                Signature = GetSignature(Resources.KsiSignature_Ok_Extended),
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                PublicationsFile = GetPublicationsFile()
            };

            VerificationResult result = policy.Verify(context);

            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(1, result.ChildResults.Count, "Invalid child result count.");
            Assert.AreEqual(nameof(PublicationBasedVerificationPolicy), result.ChildResults[result.ChildResults.Count - 1].RuleName, "Unexpected last child result rule.");
        }

        /// <summary>
        /// Signature is verified with publications file. Method Verify with publications file is used.
        /// </summary>
        [Test]
        public void VerifyWithPublicationsFile2()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            VerificationResult result = policy.Verify(GetSignature(Resources.KsiSignature_Ok_Extended),
                new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                GetPublicationsFile());

            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(1, result.ChildResults.Count, "Invalid child result count.");
            Assert.AreEqual(nameof(PublicationBasedVerificationPolicy), result.ChildResults[result.ChildResults.Count - 1].RuleName, "Unexpected last child result rule.");
        }

        /// <summary>
        /// Signature is verified with publications file, but document hash is invalid. Method Verify with publications file is used.
        /// </summary>
        [Test]
        public void VerifyWithPublicationsFileInvalidDocumentHash()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            VerificationResult result = policy.Verify(GetSignature(Resources.KsiSignature_Ok_Extended),
                // invalid document hash
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                GetPublicationsFile());

            Assert.AreEqual(VerificationResultCode.Fail, result.ResultCode);
            Assert.AreEqual(VerificationError.Gen01, result.VerificationError);
        }

        /// <summary>
        /// Signature is verified with key based policy. Method Verify with context is used.
        /// </summary>
        [Test]
        public void VerifyWithKey1()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();
            VerificationContext context = new VerificationContext()
            {
                Signature = GetSignature(Resources.KsiSignature_Ok),
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                PublicationsFile = GetPublicationsFile()
            };

            VerificationResult result = policy.Verify(context);

            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(2, result.ChildResults.Count, "Invalid child result count.");
            Assert.AreEqual(nameof(KeyBasedVerificationPolicy), result.ChildResults[result.ChildResults.Count - 1].RuleName, "Unexpected last child result rule.");
        }

        /// <summary>
        /// Signature is verified with key based policy. Method Verify with publications file is used.
        /// </summary>
        [Test]
        public void VerifyWithKey2()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            VerificationResult result = policy.Verify(GetSignature(Resources.KsiSignature_Ok),
                new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                GetPublicationsFile());

            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(2, result.ChildResults.Count, "Invalid child result count.");
            Assert.AreEqual(nameof(KeyBasedVerificationPolicy), result.ChildResults[result.ChildResults.Count - 1].RuleName, "Unexpected last child result rule.");
        }

        /// <summary>
        /// Signature verifies against publications file after automatic extending. Method Verify with context is used.
        /// </summary>
        [Test]
        public void VerifyWithExtendingAndPublicationsFile1()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();
            VerificationContext context = new VerificationContext()
            {
                Signature = GetSignature(Resources.KsiSignature_Ok),
                DocumentHash = new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                PublicationsFile = GetPublicationsFile(),
                KsiService = GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455),
                IsExtendingAllowed = true
            };

            VerificationResult result = policy.Verify(context);

            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(1, result.ChildResults.Count, "Invalid child result count.");
            Assert.AreEqual(nameof(PublicationBasedVerificationPolicy), result.ChildResults[result.ChildResults.Count - 1].RuleName, "Unexpected last child result rule.");
        }

        /// <summary>
        /// Signature verifies against publications file after automatic extending. Method Verify with KSI service is used.
        /// </summary>
        [Test]
        public void VerifyWithExtendingAndPublicationsFile2()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            VerificationResult result = policy.Verify(GetSignature(Resources.KsiSignature_Ok),
                new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")),
                GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455));

            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual(1, result.ChildResults.Count, "Invalid child result count.");
            Assert.AreEqual(nameof(PublicationBasedVerificationPolicy), result.ChildResults[result.ChildResults.Count - 1].RuleName, "Unexpected last child result rule.");
        }

        /// <summary>
        /// Invalid document hash. Method Verify with KSI service is used.
        /// </summary>
        [Test]
        public void VerifyUsingKsiServiceInvalidDocumentHash()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            VerificationResult result = policy.Verify(GetSignature(Resources.KsiSignature_Ok),
                // invalid document hash
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_RequestId_1043101455)), 1043101455));

            Assert.AreEqual(VerificationResultCode.Fail, result.ResultCode);
            Assert.AreEqual(VerificationError.Gen01, result.VerificationError);
        }

        /// <summary>
        /// Signature not verified. Calendar auth record signature certificate was not valid at aggregation time.
        /// </summary>
        [Test]
        public void VerifyWithNotValidCertAtAggregationTime()
        {
            DefaultVerificationPolicy policy = new DefaultVerificationPolicy();

            VerificationContext context = new VerificationContext()
            {
                Signature = GetSignature(Resources.KsiSignature_Invalid_Not_Valid_Cert),
                PublicationsFile = GetPublicationsFile()
            };

            VerificationResult verificationResult = policy.Verify(context);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
            Assert.AreEqual(VerificationError.Key03, verificationResult.VerificationError);
        }

        private static IKsiSignature GetSignature(string path)
        {
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory(new EmptyVerificationPolicy());
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, path), FileMode.Open))
            {
                return signatureFactory.Create(stream);
            }
        }

        private IPublicationsFile GetPublicationsFile()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiPublicationsFile), FileMode.Open, FileAccess.Read))
            {
                return new PublicationsFileFactory(new TestPkiTrustProvider()).Create(stream);
            }
        }
    }
}