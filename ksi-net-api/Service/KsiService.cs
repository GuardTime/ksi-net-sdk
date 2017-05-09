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
using System.Threading;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Utils;
using NLog;
using HashAlgorithm = Guardtime.KSI.Hashing.HashAlgorithm;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service.
    /// </summary>
    public partial class KsiService : IKsiService
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static readonly HashAlgorithm DefaultMacAlgorithm = HashAlgorithm.Sha2256;
        private const PduVersion DefaultPduVersion = PduVersion.v1;

        private readonly IKsiSigningServiceProtocol _signingServiceProtocol;
        private readonly IKsiExtendingServiceProtocol _extendingServiceProtocol;
        private readonly IKsiSignatureFactory _ksiSignatureFactory;
        private readonly IPublicationsFileFactory _publicationsFileFactory;
        private readonly IKsiPublicationsFileServiceProtocol _publicationsFileServiceProtocol;
        private readonly IServiceCredentials _signingServiceCredentials;
        private readonly IServiceCredentials _extendingServiceCredentials;
        private readonly HashAlgorithm _signingMacAlgorithm;
        private readonly HashAlgorithm _extendingMacAlgorithm;

        /// <summary>
        ///     Create KSI service with service protocol and service settings.
        /// </summary>
        /// <param name="signingServiceProtocol">signing service protocol</param>
        /// <param name="signingServiceCredentials">signing service credentials</param>
        /// <param name="extendingServiceProtocol">extending service protocol</param>
        /// <param name="extendingServiceCredentials">extending service credentials</param>
        /// <param name="publicationsFileServiceProtocol">publications file protocol</param>
        /// <param name="publicationsFileFactory">publications file factory</param>
        /// <param name="pduVersion">PDU version</param>
        public KsiService(IKsiSigningServiceProtocol signingServiceProtocol,
                          IServiceCredentials signingServiceCredentials,
                          IKsiExtendingServiceProtocol extendingServiceProtocol,
                          IServiceCredentials extendingServiceCredentials,
                          IKsiPublicationsFileServiceProtocol publicationsFileServiceProtocol,
                          IPublicationsFileFactory publicationsFileFactory,
                          PduVersion pduVersion = DefaultPduVersion)
            :
                this(signingServiceProtocol,
                    signingServiceCredentials,
                    extendingServiceProtocol,
                    extendingServiceCredentials,
                    publicationsFileServiceProtocol,
                    publicationsFileFactory,
                    new KsiSignatureFactory(),
                    pduVersion)
        {
        }

        /// <summary>
        ///     Create KSI service with service protocol and service settings.
        /// </summary>
        /// <param name="signingServiceProtocol">signing service protocol</param>
        /// <param name="signingServiceCredentials">signing service credentials</param>
        /// <param name="extendingServiceProtocol">extending service protocol</param>
        /// <param name="extendingServiceCredentials">extending service credentials</param>
        /// <param name="publicationsFileServiceProtocol">publications file protocol</param>
        /// <param name="publicationsFileFactory">publications file factory</param>
        /// <param name="ksiSignatureFactory">ksi signature factory</param>
        /// <param name="pduVersion">PDU version</param>
        public KsiService(IKsiSigningServiceProtocol signingServiceProtocol,
                          IServiceCredentials signingServiceCredentials,
                          IKsiExtendingServiceProtocol extendingServiceProtocol,
                          IServiceCredentials extendingServiceCredentials,
                          IKsiPublicationsFileServiceProtocol publicationsFileServiceProtocol,
                          IPublicationsFileFactory publicationsFileFactory,
                          IKsiSignatureFactory ksiSignatureFactory,
                          PduVersion pduVersion = DefaultPduVersion)
        {
            _signingServiceProtocol = signingServiceProtocol;
            _signingServiceCredentials = signingServiceCredentials;
            _extendingServiceProtocol = extendingServiceProtocol;
            _extendingServiceCredentials = extendingServiceCredentials;
            _publicationsFileServiceProtocol = publicationsFileServiceProtocol;
            _publicationsFileFactory = publicationsFileFactory;
            _ksiSignatureFactory = ksiSignatureFactory;
            PduVersion = pduVersion;

            _signingMacAlgorithm = _signingServiceCredentials?.MacAlgorithm ?? DefaultMacAlgorithm;
            _extendingMacAlgorithm = _extendingServiceCredentials?.MacAlgorithm ?? DefaultMacAlgorithm;
        }

        private bool IsLegacyPduVersion => PduVersion == PduVersion.v1;

        /// <summary>
        /// PDU format version
        /// </summary>
        public PduVersion PduVersion { get; }

        /// <summary>
        /// Generate new request ID
        /// </summary>
        /// <returns></returns>
        protected virtual ulong GenerateRequestId()
        {
            return Util.GetRandomUnsignedLong();
        }

        private static void ValidateLegacyResponse(LegacyPdu pdu, RequestResponsePayload payload,
                                                   ErrorPayload errorPayload, ulong requestId, HashAlgorithm expectedMacAlgorithm, IServiceCredentials serviceCredentials)
        {
            if (payload == null && errorPayload == null)
            {
                throw new KsiServiceException("Invalid response payload: null.");
            }

            if (errorPayload != null)
            {
                throw new KsiServiceException(FormatErrorStatus(errorPayload.Status, errorPayload.ErrorMessage));
            }

            CheckMacAlgorithm(pdu.Mac, expectedMacAlgorithm);

            if (!LegacyPdu.ValidateMac(pdu.Encode(), pdu.Mac, serviceCredentials.LoginKey))
            {
                throw new KsiServiceException("Invalid MAC in response PDU.");
            }

            if (payload.RequestId != requestId)
            {
                throw new KsiServiceException("Unknown request ID: " + payload.RequestId);
            }

            if (payload.Status != 0)
            {
                throw new KsiServiceException(FormatErrorStatus(payload.Status, payload.ErrorMessage));
            }
        }

        private static void ValidateResponse(byte[] data, Pdu pdu, PduPayload payload, ErrorPayload errorPayload, HashAlgorithm expectedMacAlgorithm,
                                             IServiceCredentials serviceCredentials)
        {
            if (payload == null && errorPayload == null)
            {
                throw new KsiServiceException("Invalid response PDU. Could not find a valid payload. PDU: " + pdu);
            }

            if (errorPayload != null)
            {
                throw new KsiServiceException(FormatErrorStatus(errorPayload.Status, errorPayload.ErrorMessage));
            }

            CheckMacAlgorithm(pdu.Mac, expectedMacAlgorithm);

            if (!Pdu.ValidateMac(data, pdu.Mac, serviceCredentials.LoginKey))
            {
                throw new KsiServiceException("Invalid MAC in response PDU.");
            }

            ResponsePayload responsePayload = payload as ResponsePayload;

            if (responsePayload != null && responsePayload.Status != 0)
            {
                throw new KsiServiceException(FormatErrorStatus(responsePayload.Status, responsePayload.ErrorMessage));
            }
        }

        private static void CheckMacAlgorithm(ImprintTag mac, HashAlgorithm expectedMacAlgorithm)
        {
            if (mac != null && mac.Value.Algorithm.Id != expectedMacAlgorithm.Id)
            {
                throw new KsiServiceException(string.Format("HMAC algorithm mismatch. Expected {0}, received {1}", expectedMacAlgorithm.Name, mac.Value.Algorithm.Name));
            }
        }

        private static string FormatErrorStatus(ulong status, string errorMessage)
        {
            return "Server responded with error message. Status: " + status + "; Message: " + errorMessage + ".";
        }

        /// <summary>
        ///     Abstract KSI service async result.
        /// </summary>
        private abstract class KsiServiceAsyncResult : IAsyncResult
        {
            protected KsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState)
            {
                if (serviceProtocolAsyncResult == null)
                {
                    throw new ArgumentNullException(nameof(serviceProtocolAsyncResult));
                }

                ServiceProtocolAsyncResult = serviceProtocolAsyncResult;
                AsyncState = asyncState;
            }

            public IAsyncResult ServiceProtocolAsyncResult { get; }

            public object AsyncState { get; }

            public WaitHandle AsyncWaitHandle => ServiceProtocolAsyncResult.AsyncWaitHandle;

            public bool CompletedSynchronously => ServiceProtocolAsyncResult.CompletedSynchronously;

            public bool IsCompleted => ServiceProtocolAsyncResult.IsCompleted;
        }
    }
}