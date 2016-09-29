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

using System;
using System.IO;
using System.Threading;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
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
    public class KsiService : IKsiService
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static readonly HashAlgorithm DefaultHmacAlgorithm = HashAlgorithm.Sha2256;

        /// <summary>
        /// Default PDU format version
        /// </summary>
        public const PduVersion DefaultPduVersion = PduVersion.v1;

        private readonly IKsiSigningServiceProtocol _sigingServiceProtocol;
        private readonly IKsiExtendingServiceProtocol _extendingServiceProtocol;
        private readonly IKsiSignatureFactory _ksiSignatureFactory;
        private readonly IPublicationsFileFactory _publicationsFileFactory;
        private readonly IKsiPublicationsFileServiceProtocol _publicationsFileServiceProtocol;
        private readonly IServiceCredentials _signingServiceCredentials;
        private readonly IServiceCredentials _extendingServiceCredentials;
        private readonly HashAlgorithm _hmacAlgorithm;

        /// <summary>
        ///     Create KSI service with service protocol and service settings.
        /// </summary>
        /// <param name="signingServiceProtocol">signing service protocol</param>
        /// <param name="signingServiceCredentials">signing service credentials</param>
        /// <param name="extendingServiceProtocol">extending service protocol</param>
        /// <param name="extendingServiceCredentials">extending service credentials</param>
        /// <param name="publicationsFileServiceProtocol">publications file protocol</param>
        /// <param name="publicationsFileFactory">publications file factory</param>
        public KsiService(IKsiSigningServiceProtocol signingServiceProtocol,
                          IServiceCredentials signingServiceCredentials,
                          IKsiExtendingServiceProtocol extendingServiceProtocol,
                          IServiceCredentials extendingServiceCredentials,
                          IKsiPublicationsFileServiceProtocol publicationsFileServiceProtocol,
                          IPublicationsFileFactory publicationsFileFactory)
            :
                this(signingServiceProtocol,
                    signingServiceCredentials,
                    extendingServiceProtocol,
                    extendingServiceCredentials,
                    publicationsFileServiceProtocol,
                    publicationsFileFactory,
                    new KsiSignatureFactory(),
                    DefaultHmacAlgorithm)
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
        public KsiService(IKsiSigningServiceProtocol signingServiceProtocol,
                          IServiceCredentials signingServiceCredentials,
                          IKsiExtendingServiceProtocol extendingServiceProtocol,
                          IServiceCredentials extendingServiceCredentials,
                          IKsiPublicationsFileServiceProtocol publicationsFileServiceProtocol,
                          IPublicationsFileFactory publicationsFileFactory,
                          IKsiSignatureFactory ksiSignatureFactory)
            :
                this(signingServiceProtocol,
                    signingServiceCredentials,
                    extendingServiceProtocol,
                    extendingServiceCredentials,
                    publicationsFileServiceProtocol,
                    publicationsFileFactory,
                    ksiSignatureFactory,
                    DefaultHmacAlgorithm)
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
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        public KsiService(IKsiSigningServiceProtocol signingServiceProtocol,
                          IServiceCredentials signingServiceCredentials,
                          IKsiExtendingServiceProtocol extendingServiceProtocol,
                          IServiceCredentials extendingServiceCredentials,
                          IKsiPublicationsFileServiceProtocol publicationsFileServiceProtocol,
                          IPublicationsFileFactory publicationsFileFactory,
                          HashAlgorithm hmacAlgorithm)
            :
                this(signingServiceProtocol,
                    signingServiceCredentials,
                    extendingServiceProtocol,
                    extendingServiceCredentials,
                    publicationsFileServiceProtocol,
                    publicationsFileFactory,
                    new KsiSignatureFactory(),
                    hmacAlgorithm)
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
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        public KsiService(IKsiSigningServiceProtocol signingServiceProtocol,
                          IServiceCredentials signingServiceCredentials,
                          IKsiExtendingServiceProtocol extendingServiceProtocol,
                          IServiceCredentials extendingServiceCredentials,
                          IKsiPublicationsFileServiceProtocol publicationsFileServiceProtocol,
                          IPublicationsFileFactory publicationsFileFactory,
                          IKsiSignatureFactory ksiSignatureFactory,
                          HashAlgorithm hmacAlgorithm)

        {
            if (publicationsFileFactory == null)
            {
                throw new KsiServiceException("Invalid publications file factory: null.");
            }

            _sigingServiceProtocol = signingServiceProtocol;
            _signingServiceCredentials = signingServiceCredentials;
            _extendingServiceProtocol = extendingServiceProtocol;
            _extendingServiceCredentials = extendingServiceCredentials;
            _publicationsFileServiceProtocol = publicationsFileServiceProtocol;
            _publicationsFileFactory = publicationsFileFactory;
            _ksiSignatureFactory = ksiSignatureFactory;
            _hmacAlgorithm = hmacAlgorithm;
            PduVersion = DefaultPduVersion;
        }

        /// <summary>
        /// PDU format version
        /// </summary>
        public PduVersion PduVersion { get; set; }

        /// <summary>
        ///     Create signature with given data hash (sync).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Sign(DataHash hash)
        {
            return Sign(hash, 0);
        }

        /// <summary>
        ///     Create signature with given data hash (sync)
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Sign(DataHash hash, uint level)
        {
            return EndSign(BeginSign(hash, level, null, null));
        }

        /// <summary>
        ///     Begin create signature with given data hash (async).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginSign(DataHash hash, AsyncCallback callback, object asyncState)
        {
            return BeginSign(hash, 0, callback, asyncState);
        }

        /// <summary>
        ///     Begin create signature with given data hash (async).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginSign(DataHash hash, uint level, AsyncCallback callback, object asyncState)
        {
            if (_sigingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (_signingServiceCredentials == null)
            {
                throw new KsiServiceException("Signing service credentials are missing.");
            }

            if (PduVersion == PduVersion.v1)
            {
                return BeginLegacySign(hash, level, callback, asyncState);
            }

            KsiPduHeader header = new KsiPduHeader(_signingServiceCredentials.LoginId);
            AggregationRequestPayload payload = level == 0 ? new AggregationRequestPayload(hash) : new AggregationRequestPayload(hash, level);
            AggregationRequestPdu pdu = new AggregationRequestPdu(header, payload, _hmacAlgorithm, _signingServiceCredentials.LoginKey);

            Logger.Debug("Begin sign (request id: {0}){1}{2}", payload.RequestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _sigingServiceProtocol.BeginSign(pdu.Encode(), payload.RequestId, callback, asyncState);

            return new CreateSignatureKsiServiceAsyncResult(hash, level, payload.RequestId, serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        ///     Begin create signature with given data hash (async).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        [Obsolete]
        private IAsyncResult BeginLegacySign(DataHash hash, uint level, AsyncCallback callback, object asyncState)
        {
            KsiPduHeader header = new KsiPduHeader(_signingServiceCredentials.LoginId);
            LegacyAggregationRequestPayload payload = level == 0 ? new LegacyAggregationRequestPayload(hash) : new LegacyAggregationRequestPayload(hash, level);
            LegacyAggregationPdu pdu = new LegacyAggregationPdu(header, payload, LegacyKsiPdu.GetHashMacTag(_hmacAlgorithm, _signingServiceCredentials.LoginKey, header, payload));

            Logger.Debug("Begin legacy sign (request id: {0}){1}{2}", payload.RequestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _sigingServiceProtocol.BeginSign(pdu.Encode(), payload.RequestId, callback, asyncState);

            return new CreateSignatureKsiServiceAsyncResult(hash, level, payload.RequestId, serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        ///     End create signature (async).
        /// </summary>
        /// <param name="asyncResult">async result status</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature EndSign(IAsyncResult asyncResult)
        {
            if (_sigingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (asyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult: null.");
            }

            CreateSignatureKsiServiceAsyncResult serviceAsyncResult = asyncResult as CreateSignatureKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult, could not cast to correct object.");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _sigingServiceProtocol.EndSign(serviceAsyncResult.ServiceProtocolAsyncResult);

            return ParseSignRequestResponse(data, serviceAsyncResult);
        }

        /// <summary>
        /// Parse sign request response
        /// </summary>
        /// <param name="data"></param>
        /// <param name="serviceAsyncResult"></param>
        /// <returns></returns>
        private IKsiSignature ParseSignRequestResponse(byte[] data, CreateSignatureKsiServiceAsyncResult serviceAsyncResult)
        {
            RawTag rawTag = null;
            AggregationResponsePdu pdu = null;
            LegacyAggregationPdu legacyPdu = null;

            try
            {
                if (data == null)
                {
                    throw new KsiServiceException("Invalid sign response payload: null.");
                }

                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.AggregationResponsePdu.TagType)
                {
                    pdu = new AggregationResponsePdu(rawTag);
                }
                else if (rawTag.Type == Constants.LegacyAggregationPdu.TagType)
                {
                    legacyPdu = new LegacyAggregationPdu(rawTag);
                }
                else
                {
                    throw new KsiServiceException("Unknown response PDU tag type: " + rawTag.Type.ToString("X"));
                }

                IKsiSignature signature;

                if (legacyPdu != null)
                {
                    LegacyAggregationResponsePayload legacyPayload = legacyPdu.Payload as LegacyAggregationResponsePayload;
                    LegacyAggregationErrorPayload errorPayload = legacyPdu.Payload as LegacyAggregationErrorPayload;

                    if (legacyPayload == null && errorPayload == null)
                    {
                        throw new KsiServiceException("Invalid aggregation response payload: " + legacyPdu.Payload);
                    }

                    if (legacyPayload == null || legacyPayload.Status != 0)
                    {
                        if ((legacyPayload?.Status ?? errorPayload.Status) == 0x0101)
                        {
                            if (PduVersion == PduVersion.v2)
                            {
                                throw new InvalidRequestFormatException(
                                    "Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Aggregator.");
                            }
                        }

                        string errorMessage = legacyPayload == null ? errorPayload.ErrorMessage : legacyPayload.ErrorMessage;
                        throw new KsiServiceException("Error occured during aggregation: " + errorMessage + ".");
                    }

                    if (!legacyPdu.ValidateMac(_signingServiceCredentials.LoginKey))
                    {
                        throw new KsiServiceException("Invalid HMAC in aggregation response payload.");
                    }

                    signature = _ksiSignatureFactory.Create(legacyPayload);

                    Logger.Debug("End sign successful (request id: {0}){1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, signature);
                }
                else
                {
                    AggregationResponsePayload payload = pdu.Payload as AggregationResponsePayload;
                    AggregationErrorPayload errorPayload = pdu.Payload as AggregationErrorPayload;

                    if (payload == null && errorPayload == null)
                    {
                        throw new KsiServiceException("Invalid aggregation response payload: " + pdu.Payload);
                    }

                    if (payload == null || payload.Status != 0)
                    {
                        if ((payload?.Status ?? errorPayload.Status) == 0x0101)
                        {
                            if (PduVersion == PduVersion.v1)
                            {
                                throw new InvalidRequestFormatException(
                                    "Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Aggregator.");
                            }
                        }

                        string errorMessage = payload == null ? errorPayload.ErrorMessage : payload.ErrorMessage;
                        throw new KsiServiceException("Error occured during aggregation: " + errorMessage + ".");
                    }

                    if (!pdu.ValidateMac(_signingServiceCredentials.LoginKey))
                    {
                        throw new KsiServiceException("Invalid HMAC in aggregation response payload.");
                    }

                    signature = _ksiSignatureFactory.Create(payload);

                    Logger.Debug("End sign successful (request id: {0}){1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, signature);
                }

                signature.DoInternalVerification(serviceAsyncResult.DocumentHash, serviceAsyncResult.Level);
                return signature;
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiServiceException("Could not parse response message: " + Base16.Encode(data), e);
                Logger.Warn("End sign request failed (request id: {0}): {1}", serviceAsyncResult.RequestId, ksiException);
                throw ksiException;
            }
            catch (KsiException e)
            {
                Logger.Warn("End sign request failed (request id: {0}): {1}{2}{3}", serviceAsyncResult.RequestId, e, Environment.NewLine, legacyPdu ?? pdu ?? (ITlvTag)rawTag);
                throw;
            }
        }

        /// <summary>
        /// Get additional aggergation configuration data (sync)
        /// </summary>
        /// <returns>Aggregation configuration response payload</returns>
        public AggregationConfigResponsePayload GetAggregationConfig()
        {
            return EndGetAggregationConfig(BeginGetAggregationConfig(null, null));
        }

        /// <summary>
        /// Begin get additional aggergation configuration data (async)
        /// </summary>
        /// <param name="callback"></param>
        /// <param name="asyncState"></param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetAggregationConfig(AsyncCallback callback, object asyncState)
        {
            if (PduVersion == PduVersion.v1)
            {
                throw new KsiServiceException("Config request is not supported using PDU version v1.");
            }

            if (_sigingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (_signingServiceCredentials == null)
            {
                throw new KsiServiceException("Signing service credentials are missing.");
            }

            KsiPduHeader header = new KsiPduHeader(_signingServiceCredentials.LoginId);
            AggregationConfigRequestPayload payload = new AggregationConfigRequestPayload();
            AggregationRequestPdu pdu = new AggregationRequestPdu(header, payload, _hmacAlgorithm, _signingServiceCredentials.LoginKey);

            ulong requestId = Util.GetRandomUnsignedLong();

            Logger.Debug("Begin get aggregation config (request id: {0}){1}{2}", requestId, Environment.NewLine, pdu);

            IAsyncResult serviceProtocolAsyncResult = _sigingServiceProtocol.BeginSign(pdu.Encode(), requestId, callback, asyncState);

            return new AggregationConfigKsiServiceAsyncResult(requestId, serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        /// End get additional aggergation configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Aggregation configuration response payload</returns>
        public AggregationConfigResponsePayload EndGetAggregationConfig(IAsyncResult asyncResult)
        {
            if (_sigingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (asyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult: null.");
            }

            AggregationConfigKsiServiceAsyncResult serviceAsyncResult = asyncResult as AggregationConfigKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult, could not cast to correct object.");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _sigingServiceProtocol.EndSign(serviceAsyncResult.ServiceProtocolAsyncResult);

            AggregationResponsePdu pdu = null;

            try
            {
                if (data == null)
                {
                    throw new KsiServiceException("Invalid aggregation config response payload: null.");
                }

                RawTag rawTag;

                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.LegacyAggregationPdu.TagType)
                {
                    throw new InvalidRequestFormatException("Aggregation configuration request can be used only with aggregators using PDU version v2.");
                }

                pdu = new AggregationResponsePdu(rawTag);

                KsiPduPayload ksiPduPayload = pdu.Payload;
                AggregationConfigResponsePayload payload = ksiPduPayload as AggregationConfigResponsePayload;
                AggregationErrorPayload errorPayload = ksiPduPayload as AggregationErrorPayload;

                if (payload == null && errorPayload == null)
                {
                    throw new KsiServiceException("Invalid aggregation config response payload: null.");
                }

                if (payload == null)
                {
                    throw new KsiServiceException("Error occured during aggregation config request: " + errorPayload.ErrorMessage + ".");
                }

                if (!pdu.ValidateMac(_signingServiceCredentials.LoginKey))
                {
                    throw new KsiServiceException("Invalid HMAC in aggregation config response payload.");
                }
                Logger.Debug("End get aggregation config successful (request id: {0}){1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, pdu);

                return payload;
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiServiceException("Could not parse response message: " + Base16.Encode(data), e);
                Logger.Warn("End aggregation config request failed (request id: {0}): {1}", serviceAsyncResult.RequestId, ksiException);
                throw ksiException;
            }
            catch (KsiException e)
            {
                Logger.Warn("End aggregation config request failed (request id: {0}): {1}{2}{3}", serviceAsyncResult.RequestId, e, Environment.NewLine, pdu);

                throw;
            }
        }

        /// <summary>
        ///     Extend signature to latest publication (sync).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain Extend(ulong aggregationTime)
        {
            return EndExtend(BeginExtend(aggregationTime, null, null));
        }

        /// <summary>
        ///     Extend signature to given publication (sync).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain Extend(ulong aggregationTime, ulong publicationTime)
        {
            return EndExtend(BeginExtend(aggregationTime, publicationTime, null, null));
        }

        /// <summary>
        ///     Begin extend signature to latest publication (async).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtend(ulong aggregationTime, AsyncCallback callback, object asyncState)
        {
            if (PduVersion == PduVersion.v1)
            {
                return BeginLegacyExtend(aggregationTime, null, null);
            }
            return BeginExtend(new ExtendRequestPayload(aggregationTime), callback, asyncState);
        }

        /// <summary>
        ///     Begin extend signature to given publication (async).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtend(ulong aggregationTime, ulong publicationTime, AsyncCallback callback,
                                        object asyncState)
        {
            if (PduVersion == PduVersion.v1)
            {
                return BeginLegacyExtend(aggregationTime, publicationTime, null, null);
            }

            return BeginExtend(new ExtendRequestPayload(aggregationTime, publicationTime), callback, asyncState);
        }

        /// <summary>
        ///     Begin extend with payload.
        /// </summary>
        /// <param name="payload">extend request payload</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        private IAsyncResult BeginExtend(ExtendRequestPayload payload, AsyncCallback callback, object asyncState)
        {
            if (_extendingServiceProtocol == null)
            {
                throw new KsiServiceException("Extending service protocol is missing from service.");
            }

            if (_extendingServiceCredentials == null)
            {
                throw new KsiServiceException("Extending service credentials are missing.");
            }

            KsiPduHeader header = new KsiPduHeader(_extendingServiceCredentials.LoginId);
            ExtendRequestPdu pdu = new ExtendRequestPdu(header, payload, _hmacAlgorithm, _extendingServiceCredentials.LoginKey);

            Logger.Debug("Begin extend. (request id: {0}){1}{2}", payload.RequestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _extendingServiceProtocol.BeginExtend(pdu.Encode(), payload.RequestId, callback, asyncState);

            return new ExtendSignatureKsiServiceAsyncResult(payload.RequestId, serviceProtocolAsyncResult, asyncState);
        }

        [Obsolete]
        private IAsyncResult BeginLegacyExtend(ulong aggregationTime, AsyncCallback callback, object asyncState)
        {
            return BeginLegacyExtend(new LegacyExtendRequestPayload(aggregationTime), callback, asyncState);
        }

        [Obsolete]
        private IAsyncResult BeginLegacyExtend(ulong aggregationTime, ulong publicationTime, AsyncCallback callback,
                                               object asyncState)
        {
            return BeginLegacyExtend(new LegacyExtendRequestPayload(aggregationTime, publicationTime), callback, asyncState);
        }

        [Obsolete]
        private IAsyncResult BeginLegacyExtend(LegacyExtendRequestPayload payload, AsyncCallback callback, object asyncState)
        {
            if (_extendingServiceProtocol == null)
            {
                throw new KsiServiceException("Extending service protocol is missing from service.");
            }

            if (_extendingServiceCredentials == null)
            {
                throw new KsiServiceException("Extending service credentials are missing.");
            }

            KsiPduHeader header = new KsiPduHeader(_extendingServiceCredentials.LoginId);
            LegacyExtendPdu pdu = new LegacyExtendPdu(header, payload, LegacyKsiPdu.GetHashMacTag(_hmacAlgorithm, _extendingServiceCredentials.LoginKey, header, payload));

            Logger.Debug("Begin legacy extend. (request id: {0}){1}{2}", payload.RequestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _extendingServiceProtocol.BeginExtend(pdu.Encode(), payload.RequestId, callback, asyncState);

            return new ExtendSignatureKsiServiceAsyncResult(payload.RequestId, serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        ///     End extend signature (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain EndExtend(IAsyncResult asyncResult)
        {
            if (_extendingServiceProtocol == null)
            {
                throw new KsiServiceException("Extending service protocol is missing from service.");
            }

            if (asyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult: null.");
            }

            ExtendSignatureKsiServiceAsyncResult serviceAsyncResult = asyncResult as ExtendSignatureKsiServiceAsyncResult;

            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult, could not cast to correct object.");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _extendingServiceProtocol.EndExtend(serviceAsyncResult.ServiceProtocolAsyncResult);
            return ParseExtendRequestResponse(data, serviceAsyncResult);
        }

        private CalendarHashChain ParseExtendRequestResponse(byte[] data, ExtendSignatureKsiServiceAsyncResult serviceAsyncResult)
        {
            RawTag rawTag = null;
            ExtendResponsePdu pdu = null;
            LegacyExtendPdu legacyPdu = null;

            try
            {
                if (data == null)
                {
                    throw new KsiServiceException("Invalid extend response payload: null.");
                }

                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.ExtendResponsePdu.TagType)
                {
                    pdu = new ExtendResponsePdu(rawTag);
                }
                else if (rawTag.Type == Constants.LegacyExtendPdu.TagType)
                {
                    legacyPdu = new LegacyExtendPdu(rawTag);
                }
                else
                {
                    throw new KsiServiceException("Unknown response PDU tag type: " + rawTag.Type.ToString("X"));
                }

                if (legacyPdu != null)
                {
                    LegacyExtendResponsePayload payload = legacyPdu.Payload as LegacyExtendResponsePayload;
                    LegacyExtendErrorPayload errorPayload = legacyPdu.Payload as LegacyExtendErrorPayload;

                    if (payload == null && errorPayload == null)
                    {
                        throw new KsiServiceException("Invalid extend response payload: null.");
                    }

                    if (payload == null || payload.Status != 0)
                    {
                        if ((payload?.Status ?? errorPayload.Status) == 0x0101)
                        {
                            if (PduVersion == PduVersion.v2)
                            {
                                throw new InvalidRequestFormatException("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Extender.");
                            }
                        }

                        string errorMessage = payload == null ? errorPayload.ErrorMessage : payload.ErrorMessage;
                        throw new KsiServiceException("Error occured during extending: " + errorMessage + ".");
                    }

                    if (!legacyPdu.ValidateMac(_extendingServiceCredentials.LoginKey))
                    {
                        throw new KsiServiceException("Invalid HMAC in extend response payload.");
                    }

                    if (payload.CalendarHashChain == null)
                    {
                        throw new KsiServiceException("No calendar hash chain in payload.");
                    }

                    Logger.Debug("End extend successful (request id: {0}) {1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, legacyPdu);

                    return payload.CalendarHashChain;
                }
                else
                {
                    ExtendResponsePayload payload = pdu.Payload as ExtendResponsePayload;
                    ExtendErrorPayload errorPayload = pdu.Payload as ExtendErrorPayload;

                    if (payload == null && errorPayload == null)
                    {
                        throw new KsiServiceException("Invalid extend response payload: null.");
                    }

                    if (payload == null || payload.Status != 0)
                    {
                        if ((payload?.Status ?? errorPayload.Status) == 0x0101)
                        {
                            if (PduVersion == PduVersion.v1)
                            {
                                throw new InvalidRequestFormatException("Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Extender.");
                            }
                        }

                        string errorMessage = payload == null ? errorPayload.ErrorMessage : payload.ErrorMessage;
                        throw new KsiServiceException("Error occured during extending: " + errorMessage + ".");
                    }

                    if (!pdu.ValidateMac(_extendingServiceCredentials.LoginKey))
                    {
                        throw new KsiServiceException("Invalid HMAC in extend response payload.");
                    }

                    if (payload.CalendarHashChain == null)
                    {
                        throw new KsiServiceException("No calendar hash chain in payload.");
                    }

                    Logger.Debug("End extend successful (request id: {0}) {1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, pdu);

                    return payload.CalendarHashChain;
                }
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiServiceException("Could not parse response message: " + Base16.Encode(data), e);
                Logger.Warn("End extend request failed (request id: {0}): {1}", serviceAsyncResult.RequestId, ksiException);
                throw ksiException;
            }
            catch (KsiException e)
            {
                Logger.Warn("End extend request failed (request id: {0}): {1}{2}{3}", serviceAsyncResult.RequestId, e, Environment.NewLine, legacyPdu ?? pdu ?? (ITlvTag)rawTag);
                throw;
            }
        }

        /// <summary>
        ///     Get publications file (sync).
        /// </summary>
        /// <returns>Publications file</returns>
        public IPublicationsFile GetPublicationsFile()
        {
            return EndGetPublicationsFile(BeginGetPublicationsFile(null, null));
        }

        /// <summary>
        ///     Begin get publications file (async).
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            if (_publicationsFileServiceProtocol == null)
            {
                throw new KsiServiceException("Publications file service protocol is missing from service.");
            }

            IAsyncResult serviceProtocolAsyncResult = _publicationsFileServiceProtocol.BeginGetPublicationsFile(
                callback, asyncState);
            return new PublicationKsiServiceAsyncResult(serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        ///     End get publications file (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>publications file</returns>
        public IPublicationsFile EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            if (_publicationsFileServiceProtocol == null)
            {
                throw new KsiServiceException("Publications file service protocol is missing from service.");
            }

            if (asyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult: null.");
            }

            KsiServiceAsyncResult serviceAsyncResult = asyncResult as PublicationKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult, could not cast to correct object.");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _publicationsFileServiceProtocol.EndGetPublicationsFile(serviceAsyncResult.ServiceProtocolAsyncResult);
            return _publicationsFileFactory.Create(data);
        }

        /// <summary>
        ///     Create signature KSI service async result.
        /// </summary>
        private class CreateSignatureKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public CreateSignatureKsiServiceAsyncResult(DataHash documentHash, uint level, ulong requestId, IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
                if (documentHash == null)
                {
                    throw new ArgumentNullException(nameof(documentHash));
                }

                RequestId = requestId;
                DocumentHash = documentHash;
                Level = level;
            }

            public ulong RequestId { get; }
            public DataHash DocumentHash { get; }
            public uint Level { get; }
        }

        private class AggregationConfigKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public AggregationConfigKsiServiceAsyncResult(ulong requestId, IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
                RequestId = requestId;
            }

            public ulong RequestId { get; }
        }

        /// <summary>
        ///     Extend signature KSI service async result.
        /// </summary>
        private class ExtendSignatureKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public ExtendSignatureKsiServiceAsyncResult(ulong requestId, IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
                RequestId = requestId;
            }

            public ulong RequestId { get; }
        }

        /// <summary>
        ///     Publications file KSI service async result.
        /// </summary>
        private class PublicationKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public PublicationKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
            }
        }

        /// <summary>
        ///     KSI service async result.
        /// </summary>
        private abstract class KsiServiceAsyncResult : IAsyncResult
        {
            protected KsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState)
            {
                if (serviceProtocolAsyncResult == null)
                {
                    throw new KsiServiceException("Invalid service protocol IAsyncResult: null.");
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