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
using Guardtime.KSI.Test.Signature.Verification;
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
        /// Test extending.
        /// </summary>
        [Test]
        public void ExtendStaticTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            Ksi ksi = GetKsi(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu)), 1043101455);

            ksi.Extend(signature);
        }

        /// <summary>
        /// Test extending. Response payload has non-zero status value.
        /// </summary>
        [Test]
        public void ExtendStaticWithNonZeroPayloadStatusTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            Ksi ksi = GetKsi(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_NonZeroPayloadStatus)), 0x748559A670A87D7D);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Error occured during extending. Status: 17; Message: No error."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending. PDU v2 response is returned to PDU v1 request
        /// </summary>
        [Test]
        public void ExtendStaticInvalidPduResponseVersionTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            Ksi ksi = GetKsi(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu)), 1043101455, null, PduVersion.v1);

            InvalidRequestFormatException ex = Assert.Throws<InvalidRequestFormatException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Received PDU v2 response to PDU v1 request."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending. Response PDU contains multiple payloads.
        /// </summary>
        [Test]
        public void ExtendStaticWithMultiPayloadsResponseTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            Ksi ksi = GetKsi(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_Multi_Payloads)), 8396215651691691389,
                new KsiSignatureFactory(new EmptyVerificationPolicy()));

            ksi.Extend(signature);
        }

        /// <summary>
        /// Test exteding and verification fail (calendar hash chain input hash mismatch)
        /// </summary>
        [Test]
        public void ExtendStaticInvalidCalendarHashChainTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            Ksi ksi = GetKsi(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_ExtendResponsePdu_Invalid_Signature)), 1207047688);

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Extend(signature, signature.CalendarHashChain.PublicationData);
            });

            Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.Signature);
            Assert.AreEqual(VerificationError.Int03.Code, ex.VerificationResult.VerificationError.Code);
        }

        private static Ksi GetKsi(byte[] requestResult, ulong requestId, IKsiSignatureFactory ksiSignatureFactory = null, PduVersion pduVersion = PduVersion.v2)
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                RequestResult = requestResult
            };

            return new Ksi(new TestKsiService(protocol, new ServiceCredentials("anon", "anon"), protocol, new ServiceCredentials("anon", "anon"), protocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com"))), requestId, pduVersion),
                ksiSignatureFactory);
        }
    }
}