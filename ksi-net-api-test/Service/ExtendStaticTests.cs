/*
 * Copyright 2013-2018 Guardtime, Inc.
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
using Guardtime.KSI.Test.Signature;
using Guardtime.KSI.Test.Signature.Verification;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    /// <summary>
    /// Extending tests with static response
    /// </summary>
    [TestFixture]
    public class ExtendStaticTests : StaticServiceTestsBase
    {
        /// <summary>
        /// Test extending.
        /// </summary>
        [Test]
        public void ExtendStaticTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1043101455);
            Verify(ksi.Extend(signature));
        }

        /// <summary>
        /// Test exteding with signature null
        /// </summary>
        [Test]
        public void ExtendStaticWithoutSignatureTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1043101455);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Extend(null);
            });

            Assert.AreEqual("signature", ex.ParamName);
        }

        /// <summary>
        /// Test exteding with signature null and publication data not null
        /// </summary>
        [Test]
        public void ExtendStaticWithoutSignatureWithPublicationDataTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1043101455);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Extend(null, new PublicationData(123456789, new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"))));
            });

            Assert.AreEqual("signature", ex.ParamName);
        }

        /// <summary>
        /// Test exteding with publication data null
        /// </summary>
        [Test]
        public void ExtendStaticWithPublicationDataNullTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1043101455);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Extend(new TestKsiSignature(), (PublicationData)null);
            });

            Assert.AreEqual("publicationData", ex.ParamName);
        }

        /// <summary>
        /// Test exteding with publication record null
        /// </summary>
        [Test]
        public void ExtendStaticWithPublicationRecordInPublicationsFileNullTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1043101455);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Extend(new TestKsiSignature(), (PublicationRecordInPublicationFile)null);
            });

            Assert.AreEqual("publicationRecord", ex.ParamName);
        }

        /// <summary>
        /// Test exteding with publication record null
        /// </summary>
        [Test]
        public void ExtendStaticWithPublicationRecordInSignatureNullTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1043101455);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Extend(new TestKsiSignature(), (PublicationRecordInSignature)null);
            });

            Assert.AreEqual("publicationRecord", ex.ParamName);
        }

        /// <summary>
        /// Test exteding with no suitable publication yet in publications file.
        /// </summary>
        [Test]
        public void ExtendStaticNoSuitablePublicationYetTest()
        {
            IKsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_New);
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1043101455);

            KsiException ex = Assert.Throws<KsiException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("No suitable publication yet"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending. Response payload has non-zero status value.
        /// </summary>
        [Test]
        public void ExtendStaticInvalidWithNonZeroPayloadStatusTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_NonZeroPayloadStatus, 0x748559A670A87D7D);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Server responded with error message. Status: 17; Message: No error."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending. PDU v2 response is returned to PDU v1 request
        /// </summary>
        [Test]
        public void ExtendStaticInvalidPduResponseVersionTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1043101455, null, PduVersion.v1);

            KsiServiceUnexpectedResponseFormatException ex = Assert.Throws<KsiServiceUnexpectedResponseFormatException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Received PDU v2 response to PDU v1 request."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending. Response PDU contains multiple payloads. Warning about unexpected payload is logged.
        /// </summary>
        [Test]
        public void ExtendStaticWithMultiPayloadsResponseTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            // Response has multiple payloads (2 extending payloads and a configuration payload)
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_Multi_Payloads, 1043101455, new KsiSignatureFactory(new EmptyVerificationPolicy()));
            Verify(ksi.Extend(signature));
        }

        /// <summary>
        /// Test extending. Response has invalid request id.
        /// </summary>
        [Test]
        public void ExtendStaticResponseWithWrongRequestIdTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1234567890);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Invalid response PDU. Could not find a valid payload."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test exteding and verification fail (calendar hash chain input hash mismatch)
        /// </summary>
        [Test]
        public void ExtendStaticInvalidCalendarHashChainTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_Invalid_Signature, 1207047688);

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Extend(signature, signature.CalendarHashChain.PublicationData);
            });

            Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.Signature);
            Assert.AreEqual(VerificationError.Int03.Code, ex.VerificationResult.VerificationError.Code);
        }

        /// <summary>
        /// Test extending using PDU v1.
        /// </summary>
        [Test]
        public void LegacyExtendStaticTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_LegacyExtendResponsePdu, 3491956840, null, PduVersion.v1);
            Verify(ksi.Extend(signature));
        }

        /// <summary>
        /// Test extending using PDU v2. Response contains an additional unknonwn non-critical payload. Warning about unexpected payload is logged.
        /// </summary>
        [Test]
        public void ExtendStaticWithNonCriticalPayloadTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponseNonCriticalPayload, 1043101455);
            Verify(ksi.Extend(signature));
        }

        /// <summary>
        /// Test extending using PDU v2. Response contains an additinal config payload.
        /// </summary>
        [Test]
        public void ExtendStaticWithConfTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponseWithConf, 1043101455);
            Verify(ksi.Extend(signature));
        }

        /// <summary>
        /// Test extending using PDU v2 and response has only unknown non critical payload.
        /// </summary>
        [Test]
        public void ExtendStaticResponseHasOnlyUnknownNonCriticalPayloadTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtenderResponseUnkownNonCriticalPayload, 1234567890);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Could not parse response message"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test exteding using PDU v1. Verification fail (calendar hash chain input hash mismatch)
        /// </summary>
        [Test]
        public void LegacyExtendStaticInvalidSignatureTest()
        {
            IKsiSignature signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Invalid_Calendar_Chain_Input_Hash)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_LegacyExtendResponsePdu, 3491956840, null, PduVersion.v1);

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Extend(signature, signature.CalendarHashChain.PublicationData);
            });

            Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.Signature);
            Assert.AreEqual(VerificationError.Int03.Code, ex.VerificationResult.VerificationError.Code);
        }

        /// <summary>
        /// Test extending using PDU v1. Response payload has non-zero status value.
        /// </summary>
        [Test]
        public void LegacyExtendStaticWithNonZeroPayloadStatusTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_LegacyExtendResponsePdu_NonZeroPayloadStatus, 768278381, null, PduVersion.v1);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Server responded with error message. Status: 17; Message: No error."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending with PDU containing multiple payloads including an error payload.
        /// </summary>
        [Test]
        public void ExtendStaticMultiPayloadsResponseIncludingErrorPayloadTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_Multi_Payloads_Including_ErrorPayload);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Server responded with error message. Status: 418464624128; Message: anon"), "Unexpected inner exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending with PDU containing only an error payload.
        /// </summary>
        [Test]
        public void ExtendStaticErrorPayloadTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtenderResponsePdu_ErrorPayload);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Server responded with error message. Status: 258; Message: The request could not be authenticated."),
                "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending using PDU v1. Response payload has invalid request ID.
        /// </summary>
        [Test]
        public void LegacyExtendStaticInvalidRequestIdTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_LegacyExtendResponsePdu, 0, null, PduVersion.v1);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("Unknown request ID:"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending. HMAC algorithms do no match.
        /// </summary>
        [Test]
        public void ExtendStaticInvalidMacAlgorithmTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_ExtendResponsePdu_RequestId_1043101455, 1043101455, null, PduVersion.v2, null, HashAlgorithm.Sha2512);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("HMAC algorithm mismatch."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test extending using PDU v1. HMAC algorithms do no match.
        /// </summary>
        [Test]
        public void LegacyExtendStaticInvalidMacAlgorithmTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok)));
            Ksi ksi = GetStaticKsi(Resources.KsiService_LegacyExtendResponsePdu, 3491956840, null, PduVersion.v1, null, HashAlgorithm.Sha2512);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Extend(signature);
            });

            Assert.That(ex.Message.StartsWith("HMAC algorithm mismatch."), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void BeginExtendWithoutExtendingServiceProtocol()
        {
            KsiService service = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.BeginExtend(1, null, null);
            });

            Assert.That(ex.Message.StartsWith("Extending service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void BeginExtendWithoutExtendingServiceCredentials()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol();
            KsiService service = new KsiService(null, null, protocol, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.BeginExtend(1, null, null);
            });

            Assert.That(ex.Message.StartsWith("Extending service credentials are missing."), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndExtendArgumentNullTest()
        {
            IKsiService service = GetStaticKsiService(new byte[] { 0 });

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                service.EndExtend(null);
            });
            Assert.AreEqual("asyncResult", ex.ParamName);
        }

        [Test]
        public void EndExtendInvalidAsyncResultTest()
        {
            IKsiService service = GetStaticKsiService(new byte[] { 0 });

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndExtend(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Invalid asyncResult type:"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndExtendWithoutExtendingServiceProtocol()
        {
            KsiService service = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndExtend(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Extending service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        private static void Verify(IKsiSignature signature)
        {
            Assert.IsTrue(signature.IsExtended, "");

            IVerificationContext context = new VerificationContext()
            {
                Signature = signature,
            };
            VerificationResult result = new InternalVerificationPolicy().Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result");
        }
    }
}