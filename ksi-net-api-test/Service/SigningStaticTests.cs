﻿/*
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
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    /// <summary>
    /// Signing tests with static response
    /// </summary>
    [TestFixture]
    public class SigningStaticTests : StaticServiceTestsBase
    {
        /// <summary>
        /// Test creating Ksi with service null.
        /// </summary>
        [Test]
        public void CreateKsiWithServiceNull()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                Ksi ksi = new Ksi(null);
            });

            Assert.AreEqual("ksiService", ex.ParamName);
        }

        /// <summary>
        /// Test signing.
        /// </summary>
        [Test]
        public void SignStaticTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_RequestId_1584727637, 1584727637);
            DataHash dataHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = ksi.Sign(dataHash);
            Verify(signature, dataHash);
        }

        /// <summary>
        /// Test signing with data hash null.
        /// </summary>
        [Test]
        public void SignStaticDataHashNullTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_RequestId_1584727637, 1584727637);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Sign((DataHash)null);
            });

            Assert.AreEqual("hash", ex.ParamName);
        }

        /// <summary>
        /// Test signing with byte array null.
        /// </summary>
        [Test]
        public void SignStaticByteArrayNullTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_RequestId_1584727637, 1584727637);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Sign((byte[])null);
            });

            Assert.AreEqual("documentBytes", ex.ParamName);
        }

        /// <summary>
        /// Test signing with empty byte array.
        /// </summary>
        [Test]
        public void SignStaticByteArrayEmptyTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_SignedZeroBytes, 6607061513599596791);
            byte[] documentBytes = new byte[] { };
            IKsiSignature signature = ksi.Sign(documentBytes);
            Verify(signature, KsiProvider.CreateDataHasher(HashAlgorithm.Default).AddData(documentBytes).GetHash());
        }

        /// <summary>
        /// Test signing with data stream null.
        /// </summary>
        [Test]
        public void SignStaticStreamNullTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_RequestId_1584727637, 1584727637);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                ksi.Sign((Stream)null);
            });

            Assert.AreEqual("stream", ex.ParamName);
        }

        /// <summary>
        /// Test signing with empty data stream.
        /// </summary>
        [Test]
        public void SignStaticStreamEmptyTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_SignedZeroBytes, 6607061513599596791);
            IKsiSignature signature;
            using (MemoryStream stream = new MemoryStream())
            {
                signature = ksi.Sign(stream);
            }

            byte[] documentBytes = new byte[] { };
            Verify(signature, KsiProvider.CreateDataHasher(HashAlgorithm.Default).AddData(documentBytes).GetHash());
        }

        /// <summary>
        /// Test signing with closed data stream.
        /// </summary>
        [Test]
        public void SignStaticStreamClosedTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_SignedZeroBytes, 6607061513599596791);
            MemoryStream stream = new MemoryStream();
            stream.Close();

            ObjectDisposedException ex = Assert.Throws<ObjectDisposedException>(delegate
            {
                ksi.Sign(stream);
            });

            Assert.That(ex.Message.StartsWith("Cannot access a closed Stream."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing using PDU v1.
        /// </summary>
        [Test]
        public void LegacySignStaticTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_LegacyAggregationResponsePdu, 318748698, null, PduVersion.v1);

            DataHash dataHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = ksi.Sign(dataHash);
            Verify(signature, dataHash);
        }

        /// <summary>
        /// Test signing. PDU v2 response is returned to PDU v1 request.
        /// </summary>
        [Test]
        public void SignStaticInvalidPduResponseVersionTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_RequestId_1584727637, 1584727637, null, PduVersion.v1);

            KsiServiceUnexpectedResponseFormatException ex = Assert.Throws<KsiServiceUnexpectedResponseFormatException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Received PDU v2 response to PDU v1 request."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing. Response PDU contains multiple payloads. Warning about unexpected payload is logged.
        /// </summary>
        [Test]
        public void SignStaticWithMultiPayloadsResponseTest()
        {
            // Response has multiple payloads (2 signature payloads and a configuration payload)
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_Multi_Payloads, 1584727637);
            DataHash dataHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = ksi.Sign(dataHash);
            Verify(signature, dataHash);
        }

        /// <summary>
        /// Test signing. Response PDU contains a config payload and an acknowledgment payload.
        /// </summary>
        [Test]
        public void SignStaticWithConfigAndAcknowledgmentTest()
        {
            // Response has multiple payloads (1 signature payload, a config payload and an acknowledgment payload)
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_With_Config_And_Acknowledgment, 1584727637);
            DataHash dataHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = ksi.Sign(dataHash);
            Verify(signature, dataHash);
        }

        /// <summary>
        /// Test signing. Response has invalid request ID.
        /// </summary>
        [Test]
        public void SignStaticResponseWithWrongRequestIdTest()
        {
            // Response has additional unknown non-ciritcal payload.
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_RequestId_1584727637, 1234567890);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            });

            Assert.That(ex.Message.StartsWith("Invalid response PDU. Could not find a valid payload."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing. Response has not requested conf.
        /// </summary>
        [Test]
        public void SignStaticWithConfTest()
        {
            // Response has additional conf.
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponseWithConf, 1584727637);
            DataHash dataHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = ksi.Sign(dataHash);
            Verify(signature, dataHash);
        }

        /// <summary>
        /// Test signing. Response has additinal unknown non-ciritcal payload. Warning about unexpected payload is logged.
        /// </summary>
        [Test]
        public void SignStaticWithUnknownNonCriticalPayloadTest()
        {
            // Response has additional unknown non-ciritcal payload.
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponseWithUnknownNonCriticalPayload, 1584727637);
            DataHash dataHash = new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            IKsiSignature signature = ksi.Sign(dataHash);
            Verify(signature, dataHash);
        }

        /// <summary>
        /// Test signing. Response has only unknown non-ciritcal payload.
        /// </summary>
        [Test]
        public void SignStaticResponseHasOnlyUnknownNonCriticalPayloadTest()
        {
            // Response has only unknown non-ciritcal payload.
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponseUnknownNonCriticalPayload, 1234567890);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")));
            });

            Assert.That(ex.Message.StartsWith("Could not parse response message"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing and verification fail.
        /// </summary>
        [Test]
        public void SignStaticInvalidSignatureTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_Invalid_Signature, 2);

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.Signature);
            Assert.AreEqual(VerificationError.Int01.Code, ex.VerificationResult.VerificationError.Code);
        }

        /// <summary>
        /// Test signing using PDU v1. Verification fail.
        /// </summary>
        [Test]
        public void LegacySignStaticInvalidSignatureTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_LegacyAggregationResponsePdu, 318748698, null, PduVersion.v1);

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("01A1A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.Signature);
            Assert.AreEqual(VerificationError.Gen01.Code, ex.VerificationResult.VerificationError.Code);
        }

        /// <summary>
        /// Test signing with PDU containing multiple payloads including an error payload.
        /// </summary>
        [Test]
        public void SignStaticMultiPayloadsResponseIncludingErrorPayloadTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_Multi_Payloads_Including_ErrorPayload, 2);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Server responded with error message. Status: 418464624128; Message: anon"), "Unexpected inner exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with PDU containing only an error payload.
        /// </summary>
        [Test]
        public void SignStaticErrorPayloadTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_ErrorPayload, 2);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Server responded with error message. Status: 258; Message: The request could not be authenticated."),
                "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing using PDU v1. Response payload has invalid request ID.
        /// </summary>
        [Test]
        public void LegacySignStaticInvalidRequestIdTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_LegacyAggregationResponsePdu, 0, null, PduVersion.v1);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Unknown request ID:"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with level 2. Level correction in response is 1.
        /// </summary>
        [Test]
        public void SignStaticWithLevelTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_SignedLevel2_LevelCorrection1, 3306651419058286509);
            DataHash documentHash = new DataHash(HashAlgorithm.Sha2256, Base16.Decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));

            IKsiSignature signature = ksi.Sign(documentHash, 2);

            Assert.AreEqual(3, signature.GetAggregationHashChains()[0].GetChainLinks()[0].LevelCorrection, "Level correction is invalid.");
        }

        /// <summary>
        /// Test signing. HMAC algorithms do no match.
        /// </summary>
        [Test]
        public void SignStaticInvalidMacAlgorithmTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_RequestId_1584727637, 1584727637, null, PduVersion.v2, HashAlgorithm.Sha2512);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("HMAC algorithm mismatch."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing using PDU v1. HMAC algorithms do no match.
        /// </summary>
        [Test]
        public void LegacySignStaticInvalidMacAlgorithmTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_LegacyAggregationResponsePdu, 318748698, null, PduVersion.v1, HashAlgorithm.Sha2512);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("HMAC algorithm mismatch."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing. Invalid HMAC.
        /// </summary>
        [Test]
        public void SignStaticInvalidMacTest()
        {
            Ksi ksi = GetStaticKsi(Resources.KsiService_AggregationResponsePdu_Invalid_Mac, 1584727637);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Invalid MAC in response PDU."), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with invalid response PDU type.
        /// </summary>
        [Test]
        public void SignStaticInvalidPduTypeTest()
        {
            Ksi ksi = GetStaticKsi(new byte[] { 1, 2, 3, 4, 5 });

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Unknown response PDU tag type"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with invalid response PDU content.
        /// </summary>
        [Test]
        public void SignStaticInvalidPduContentTest()
        {
            Ksi ksi = GetStaticKsi(new byte[] { 0x82, 0x21, 0x08, 0xA7, 0x01 });

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });

            Assert.That(ex.Message.StartsWith("Could not parse response message"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// Test signing with deprecated input hash algorithm.
        /// </summary>
        [Test]
        public void SignStaticWithDeprecatedInputHashAlgorithmTest()
        {
            Ksi ksi = GetStaticKsi(new byte[] { });

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                ksi.Sign(new DataHash(Base16.Decode("0011A700B0C8066C47ECBA05ED37BC14DCADB23855")));
            });

            Assert.That(ex.Message.StartsWith("Hash algorithm SHA1 is deprecated since 2016-07-01 and can not be used for signing."),
                "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void BeginSignWithoutSigningServiceProtocol()
        {
            KsiService service = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.BeginSign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")), null, null);
            });

            Assert.That(ex.Message.StartsWith("Signing service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void BeginSignWithoutSigningServiceCredentials()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol();
            KsiService service = new KsiService(protocol, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.BeginSign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")), null, null);
            });

            Assert.That(ex.Message.StartsWith("Signing service credentials are missing."), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void BeginSignWithHashNullTest()
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol();
            KsiService service = new KsiService(protocol, new ServiceCredentials(TestConstants.ServiceUser, TestConstants.ServicePass), null, null, null, null);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                service.BeginSign(null, null, null);
            });
            Assert.AreEqual("hash", ex.ParamName);
        }

        [Test]
        public void EndSignArgumentNullTest()
        {
            IKsiService service = GetStaticKsiService(new byte[] { 0 });

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                service.EndSign(null);
            });
            Assert.AreEqual("asyncResult", ex.ParamName);
        }

        [Test]
        public void EndSignInvalidAsyncResultTest()
        {
            IKsiService service = GetStaticKsiService(new byte[] { 0 });

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                service.EndSign(new TestAsyncResult());
            });

            Assert.That(ex.Message.StartsWith("Invalid asyncResult type:"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndSignWithoutSigningServiceProtocol()
        {
            IKsiService serviceBegin = GetStaticKsiService(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiService_AggregationResponsePdu_RequestId_1584727637)),
                1584727637);
            IAsyncResult asyncResult = serviceBegin.BeginSign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")), null, null);
            KsiService serviceEnd = new KsiService(null, null, null, null, null, null);

            KsiServiceException ex = Assert.Throws<KsiServiceException>(delegate
            {
                serviceEnd.EndSign(asyncResult);
            });

            Assert.That(ex.Message.StartsWith("Signing service protocol is missing from service"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void EndSignWithSigningServiceProtocolResultNull()
        {
            KsiService service = new KsiService(new TestKsiServiceProtocol(), new ServiceCredentials(TestConstants.ServiceUser, TestConstants.ServicePass), null, null, null, null);

            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                service.Sign(new DataHash(Base16.Decode("0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
            });
            Assert.AreEqual("data", ex.ParamName);
        }

        private static void Verify(IKsiSignature signature, DataHash dataHash)
        {
            IVerificationContext context = new VerificationContext()
            {
                Signature = signature,
                DocumentHash = dataHash
            };
            VerificationResult result = new InternalVerificationPolicy().Verify(context);
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result");
        }
    }
}