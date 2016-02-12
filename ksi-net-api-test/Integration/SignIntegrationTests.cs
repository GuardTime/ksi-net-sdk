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
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Integration
{
    [TestFixture]
    public class SignIntegrationTests : IntegrationTests
    {
        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void HttpSignHashTest(Ksi ksi)
        {
            VerificationResult verificationResult = SignHashTest(ksi);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidPass))]
        public void HttpSignHashInvalidPassTest(Ksi ksi)
        {
            Assert.Throws<KsiServiceException>(delegate
            {
                SignHashTest(ksi);
            });
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCasesInvalidUrl))]
        public void HttpSignHashInvalidUrlTest(Ksi ksi)
        {
            Assert.Throws<KsiServiceProtocolException>(delegate
            {
                SignHashTest(ksi);
            });
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void TcpSignHashTest(Ksi ksi)
        {
            VerificationResult verificationResult = SignHashTest(ksi);
            Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode, "Signature should verify with key based policy");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCasesInvalidPass))]
        public void TcpSignHashInvalidPassTest(Ksi ksi)
        {
            Assert.Throws<KsiServiceException>(delegate
            {
                SignHashTest(ksi);
            });
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCasesInvalidUrl))]
        public void TcpSignHashInvalidUrlTest(Ksi ksi)
        {
            Assert.Throws<KsiServiceProtocolException>(delegate
            {
                SignHashTest(ksi);
            });
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCasesInvalidPort))]
        public void TcpSignHashInvalidPortTest(Ksi ksi)
        {
            Assert.Throws<KsiServiceProtocolException>(delegate
            {
                SignHashTest(ksi);
            });
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(HttpTestCases))]
        public void HttpSignedHashVerifyWithInvalidHashTest(Ksi ksi)
        {
            VerificationResult verificationResult = SignedHashVerifyWithInvalidHashTest(ksi);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode, "Invalid hash should not verify with key based policy");
        }

        [Test, TestCaseSource(typeof(IntegrationTests), nameof(TcpTestCases))]
        public void TcpSignedHashVerifyWithInvalidHashTest(Ksi ksi)
        {
            VerificationResult verificationResult = SignedHashVerifyWithInvalidHashTest(ksi);
            Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode, "Invalid hash should not verify with key based policy");
        }

        public VerificationResult SignHashTest(Ksi ksi)
        {
            IKsiSignature signature = ksi.Sign(new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            VerificationContext verificationContext = new VerificationContext(signature)
            {
                DocumentHash = new DataHash(HashAlgorithm.Sha2256,
                    Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")),
                PublicationsFile = ksi.GetPublicationsFile()
            };
            return ksi.Verify(verificationContext,
                new KeyBasedVerificationPolicy(new X509Store(StoreName.Root), new CertificateSubjectRdnSelector("E=publications@guardtime.com")));
        }

        public VerificationResult SignedHashVerifyWithInvalidHashTest(Ksi ksi)
        {
            using (MemoryStream memoryStream = new MemoryStream(Encoding.UTF8.GetBytes("test")))
            {
                DataHasher dataHasher = new DataHasher(HashAlgorithm.Sha2256);
                dataHasher.AddData(memoryStream);
                IKsiSignature signature = ksi.Sign(dataHasher.GetHash());

                VerificationContext verificationContext = new VerificationContext(signature)
                {
                    DocumentHash = new DataHash(HashAlgorithm.Sha2256,
                        Base16.Decode("1f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")),
                    PublicationsFile = ksi.GetPublicationsFile()
                };
                return ksi.Verify(verificationContext,
                    new KeyBasedVerificationPolicy(new X509Store(StoreName.Root), new CertificateSubjectRdnSelector("E=publications@guardtime.com")));
            }
        }
    }
}