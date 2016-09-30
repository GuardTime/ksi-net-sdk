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
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    /// <summary>
    /// Extending tests with static response
    /// </summary>
    [TestFixture]
    public class ExtendStaticTests
    {
        /// <summary>
        /// Test extending and verifying
        /// </summary>
        [Test]
        public void ExtendAndVerifyStaticTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            Ksi ksi = GetKsi(signature.CalendarHashChain);

            ksi.Extend(signature, signature.CalendarHashChain.PublicationData);
        }

        /// <summary>
        /// Test exteding and verification fail
        /// </summary>
        [Test]
        public void ExtendAndVerifyInvalidStaticTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            CalendarHashChain calendarHashChain = new KsiSignatureFactory() { DisableVerification = true }.
                Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Invalid_Calendar_Chain_Input_Hash))).CalendarHashChain;

            Ksi ksi = GetKsi(calendarHashChain);

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Extend(signature, calendarHashChain.PublicationData);
            });

            Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.Signature);
            Assert.AreEqual(VerificationError.Int03.Code, ex.VerificationResult.VerificationError.Code);
        }

        private static Ksi GetKsi(CalendarHashChain extendResult)
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                ExtendResult = extendResult
            };

            return new Ksi(new KsiService(protocol, new ServiceCredentials("test", "test"), protocol, new ServiceCredentials("test", "test"), protocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com")))));
        }
    }
}