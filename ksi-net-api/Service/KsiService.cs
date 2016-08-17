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
        private static bool _useLegacyRequestFormat;
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static readonly HashAlgorithm DefaultHmacAlgorithm = HashAlgorithm.Sha2256;

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
                throw new KsiException("Invalid publications file factory: null.");
            }

            _sigingServiceProtocol = signingServiceProtocol;
            _signingServiceCredentials = signingServiceCredentials;
            _extendingServiceProtocol = extendingServiceProtocol;
            _extendingServiceCredentials = extendingServiceCredentials;
            _publicationsFileServiceProtocol = publicationsFileServiceProtocol;
            _publicationsFileFactory = publicationsFileFactory;
            _ksiSignatureFactory = ksiSignatureFactory;
            _hmacAlgorithm = hmacAlgorithm;
        }

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
            try
            {
                return EndSign(_useLegacyRequestFormat ? BeginLegacySign(hash, level, null, null) : BeginSign(hash, level, null, null));
            }
            catch (InvalidRequestFormatException e)
            {
                if (_useLegacyRequestFormat)
                {
                    _useLegacyRequestFormat = false;
                    Logger.Debug("Invalid request format. Used format: legacy. " + e.Message);
                    Logger.Debug("Trying to use different format: new.");

                    return EndSign(BeginSign(hash, level, null, null));
                }
                else
                {
                    _useLegacyRequestFormat = true;
                    Logger.Debug("Invalid request format. Used format: new. " + e.Message);
                    Logger.Debug("Trying to use different format: legacy.");

                    return EndSign(BeginLegacySign(hash, level, null, null));
                }
            }
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
                throw new KsiException("Signing service credentials are missing.");
            }

            KsiPduHeader header = new KsiPduHeader(_signingServiceCredentials.LoginId);
            AggregationRequestPayload payload = level == 0 ? new AggregationRequestPayload(hash) : new AggregationRequestPayload(hash, level);
            AggregationPdu pdu = new AggregationPdu(header, payload, _hmacAlgorithm, _signingServiceCredentials.LoginKey);

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
            if (_sigingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (_signingServiceCredentials == null)
            {
                throw new KsiException("Signing service credentials are missing.");
            }

            KsiPduHeader header = new KsiPduHeader(_signingServiceCredentials.LoginId);
            AggregationRequestPayload payload = level == 0 ? new AggregationRequestPayload(hash) : new AggregationRequestPayload(hash, level);
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
                throw new KsiException("Invalid IAsyncResult: null.");
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
            AggregationPdu pdu = null;
            LegacyAggregationPdu legacyPdu = null;

            try
            {
                if (data == null)
                {
                    throw new KsiException("Invalid sign response payload: null.");
                }

                RawTag rawTag;
                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.AggregationPdu.TagType)
                {
                    pdu = new AggregationPdu(rawTag);
                }
                else
                {
                    legacyPdu = new LegacyAggregationPdu(rawTag);
                }

                KsiPduPayload ksiPduPayload = legacyPdu != null ? legacyPdu.Payload : pdu.Payload;
                AggregationResponsePayload payload = ksiPduPayload as AggregationResponsePayload;
                AggregationErrorPayload errorPayload = ksiPduPayload as AggregationErrorPayload;

                if (payload == null && errorPayload == null)
                {
                    throw new KsiException("Invalid aggregation response payload: null.");
                }

                if (payload == null || payload.Status != 0)
                {
                    if ((payload?.Status ?? errorPayload.Status) == 0x0101)
                    {
                        throw new InvalidRequestFormatException("Expected format: " + (legacyPdu != null ? "legacy" : "new"));
                    }

                    string errorMessage = payload == null ? errorPayload.ErrorMessage : payload.ErrorMessage;
                    throw new KsiServiceException("Error occured during aggregation: " + errorMessage + ".");
                }

                if (legacyPdu != null)
                {
                    if (!legacyPdu.ValidateMac(_signingServiceCredentials.LoginKey))
                    {
                        throw new KsiServiceException("Invalid HMAC in aggregation response payload");
                    }
                    Logger.Debug("End sign successful (request id: {0}){1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, legacyPdu);
                }
                else
                {
                    if (!pdu.ValidateMac(_signingServiceCredentials.LoginKey))
                    {
                        throw new KsiServiceException("Invalid HMAC in aggregation response payload");
                    }
                    Logger.Debug("End sign successful (request id: {0}){1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, pdu);
                }

                IKsiSignature signature = _ksiSignatureFactory.Create(payload);
                signature.DoInternalVerification(serviceAsyncResult.DocumentHash, serviceAsyncResult.Level);
                return signature;
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiException("Could not parse response message: " + Base16.Encode(data), e);
                Logger.Warn("End sign request failed (request id: {0}): {1}", serviceAsyncResult.RequestId, ksiException);
                throw ksiException;
            }
            catch (KsiException e)
            {
                if (legacyPdu != null)
                {
                    Logger.Warn("End sign request failed (request id: {0}): {1}{2}{3}", serviceAsyncResult.RequestId, e, Environment.NewLine, legacyPdu);
                }
                else
                {
                    Logger.Warn("End sign request failed (request id: {0}): {1}{2}{3}", serviceAsyncResult.RequestId, e, Environment.NewLine, pdu);
                }

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
            if (_sigingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (_signingServiceCredentials == null)
            {
                throw new KsiException("Signing service credentials are missing.");
            }

            KsiPduHeader header = new KsiPduHeader(_signingServiceCredentials.LoginId);
            AggregationConfigRequestPayload payload = new AggregationConfigRequestPayload();
            AggregationPdu pdu = new AggregationPdu(header, payload, _hmacAlgorithm, _signingServiceCredentials.LoginKey);

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
                throw new KsiException("Invalid IAsyncResult: null.");
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

            AggregationPdu pdu = null;

            try
            {
                if (data == null)
                {
                    throw new KsiException("Invalid aggregation config response payload: null.");
                }

                RawTag rawTag;

                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.LegacyAggregationPdu.TagType)
                {
                    throw new InvalidRequestFormatException("Aggregation configuration request can be used only with aggregators using new request format.");
                }

                pdu = new AggregationPdu(rawTag);

                KsiPduPayload ksiPduPayload = pdu.Payload;
                AggregationConfigResponsePayload payload = ksiPduPayload as AggregationConfigResponsePayload;
                AggregationErrorPayload errorPayload = ksiPduPayload as AggregationErrorPayload;

                if (payload == null && errorPayload == null)
                {
                    throw new KsiException("Invalid aggregation config response payload: null.");
                }

                if (payload == null)
                {
                    throw new KsiServiceException("Error occured during aggregation config request: " + errorPayload.ErrorMessage + ".");
                }

                if (!pdu.ValidateMac(_signingServiceCredentials.LoginKey))
                {
                    throw new KsiServiceException("Invalid HMAC in aggregation config response payload");
                }
                Logger.Debug("End sign successful (request id: {0}){1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, pdu);

                return payload;
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiException("Could not parse response message: " + Base16.Encode(data), e);
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
            try
            {
                return _useLegacyRequestFormat ? EndExtend(BeginLegacyExtend(aggregationTime, null, null)) : EndExtend(BeginExtend(aggregationTime, null, null));
            }
            catch (InvalidRequestFormatException e)
            {
                if (_useLegacyRequestFormat)
                {
                    _useLegacyRequestFormat = false;
                    Logger.Debug("Invalid request format. Used format: legacy. " + e.Message);
                    Logger.Debug("Trying to use different format: new.");

                    return EndExtend(BeginExtend(aggregationTime, null, null));
                }
                else
                {
                    _useLegacyRequestFormat = true;
                    Logger.Debug("Invalid request format. Used format: new. " + e.Message);
                    Logger.Debug("Trying to use different format: legacy.");

                    return EndExtend(BeginLegacyExtend(aggregationTime, null, null));
                }
            }
        }

        /// <summary>
        ///     Extend signature to given publication (sync).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain Extend(ulong aggregationTime, ulong publicationTime)
        {
            try
            {
                return _useLegacyRequestFormat
                    ? EndExtend(BeginLegacyExtend(aggregationTime, publicationTime, null, null))
                    : EndExtend(BeginExtend(aggregationTime, publicationTime, null, null));
            }
            catch (InvalidRequestFormatException e)
            {
                if (_useLegacyRequestFormat)
                {
                    _useLegacyRequestFormat = false;
                    Logger.Debug("Invalid request format. Used format: legacy. " + e.Message);
                    Logger.Debug("Trying to use different format: new.");

                    return EndExtend(BeginExtend(aggregationTime, publicationTime, null, null));
                }
                else
                {
                    _useLegacyRequestFormat = true;
                    Logger.Debug("Invalid request format. Used format: new. " + e.Message);
                    Logger.Debug("Trying to use different format: legacy.");

                    return EndExtend(BeginLegacyExtend(aggregationTime, publicationTime, null, null));
                }
            }
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
                throw new KsiException("Extending service credentials are missing.");
            }

            KsiPduHeader header = new KsiPduHeader(_extendingServiceCredentials.LoginId);
            ExtendPdu pdu = new ExtendPdu(header, payload, _hmacAlgorithm, _extendingServiceCredentials.LoginKey);

            Logger.Debug("Begin extend. (request id: {0}){1}{2}", payload.RequestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _extendingServiceProtocol.BeginExtend(pdu.Encode(), payload.RequestId, callback, asyncState);

            return new ExtendSignatureKsiServiceAsyncResult(payload.RequestId, serviceProtocolAsyncResult, asyncState);
        }

        [Obsolete]
        private IAsyncResult BeginLegacyExtend(ulong aggregationTime, AsyncCallback callback, object asyncState)
        {
            return BeginLegacyExtend(new ExtendRequestPayload(aggregationTime), callback, asyncState);
        }

        [Obsolete]
        private IAsyncResult BeginLegacyExtend(ulong aggregationTime, ulong publicationTime, AsyncCallback callback,
                                               object asyncState)
        {
            return BeginLegacyExtend(new ExtendRequestPayload(aggregationTime, publicationTime), callback, asyncState);
        }

        [Obsolete]
        private IAsyncResult BeginLegacyExtend(ExtendRequestPayload payload, AsyncCallback callback, object asyncState)
        {
            if (_extendingServiceProtocol == null)
            {
                throw new KsiServiceException("Extending service protocol is missing from service.");
            }

            if (_extendingServiceCredentials == null)
            {
                throw new KsiException("Extending service credentials are missing.");
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
                throw new KsiException("Invalid IAsyncResult: null.");
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
            ExtendPdu pdu = null;
            LegacyExtendPdu legacyPdu = null;

            try
            {
                if (data == null)
                {
                    throw new KsiException("Invalid extend response payload: null.");
                }

                RawTag rawTag;
                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.ExtendPdu.TagType)
                {
                    pdu = new ExtendPdu(rawTag);
                }
                else
                {
                    legacyPdu = new LegacyExtendPdu(rawTag);
                }

                KsiPduPayload ksiPduPayload = legacyPdu != null ? legacyPdu.Payload : pdu.Payload;
                ExtendResponsePayload payload = ksiPduPayload as ExtendResponsePayload;
                ExtendErrorPayload errorPayload = ksiPduPayload as ExtendErrorPayload;

                if (payload == null && errorPayload == null)
                {
                    throw new KsiException("Invalid extend response payload: null.");
                }

                if (payload == null || payload.Status != 0)
                {
                    if ((payload?.Status ?? errorPayload.Status) == 0x0101)
                    {
                        throw new InvalidRequestFormatException("Expected format: " + (legacyPdu != null ? "legacy" : "new"));
                    }

                    string errorMessage = payload == null ? errorPayload.ErrorMessage : payload.ErrorMessage;
                    throw new KsiException("Error occured during extending: " + errorMessage + ".");
                }

                if (pdu != null)
                {
                    if (!pdu.ValidateMac(_extendingServiceCredentials.LoginKey))
                    {
                        throw new KsiServiceException("Invalid HMAC in extend response payload");
                    }

                    if (payload.CalendarHashChain == null)
                    {
                        throw new KsiServiceException("No calendar hash chain in payload.");
                    }

                    Logger.Debug("End extend successful (request id: {0}) {1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, pdu);
                }
                else
                {
                    if (!legacyPdu.ValidateMac(_extendingServiceCredentials.LoginKey))
                    {
                        throw new KsiServiceException("Invalid HMAC in extend response payload");
                    }

                    if (payload.CalendarHashChain == null)
                    {
                        throw new KsiServiceException("No calendar hash chain in payload.");
                    }

                    Logger.Debug("End extend successful (request id: {0}) {1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, legacyPdu);
                }

                return payload.CalendarHashChain;
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiException("Could not parse response message: " + Base16.Encode(data), e);
                Logger.Warn("End extend request failed (request id: {0}): {1}", serviceAsyncResult.RequestId, ksiException);
                throw ksiException;
            }
            catch (KsiException e)
            {
                if (pdu != null)
                {
                    Logger.Warn("End extend request failed (request id: {0}): {1}{2}{3}", serviceAsyncResult.RequestId, e, Environment.NewLine, pdu);
                }
                else
                {
                    Logger.Warn("End extend request failed (request id: {0}): {1}{2}{3}", serviceAsyncResult.RequestId, e, Environment.NewLine, legacyPdu);
                }

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
                throw new KsiException("Invalid IAsyncResult: null.");
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
                    throw new KsiException("Invalid service protocol IAsyncResult: null.");
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