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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    /// <summary>
    /// Signing tests with static response
    /// </summary>
    [TestFixture]
    public class SigningStaticTests
    {
        /// <summary>
        /// Test signing and verifying
        /// </summary>
        [Test]
        public void SignAndVerifyStaticTest()
        {
            Ksi ksi = GetKsi(new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok))));

            ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
        }

        /// <summary>
        /// Test signing and verification fail.
        /// </summary>
        [Test]
        public void SignAndVerifyInvalidStaticTest()
        {
            Ksi ksi = GetKsi(new KsiSignatureFactory() { DisableVerification = true }.Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Invalid_Aggregation_Chain_Input_Hash))));

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.Signature);
            Assert.AreEqual(VerificationError.Int01.Code, ex.VerificationResult.VerificationError.Code);
        }

        private static Ksi GetKsi(IKsiSignature signResultSignature)
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                SignResult = signResultSignature
            };

            return new Ksi(new KsiService(protocol, new ServiceCredentials("test", "test"), protocol, new ServiceCredentials("test", "test"), protocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com")))));
        }
    }
}