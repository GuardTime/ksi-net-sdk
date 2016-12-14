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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service.
    /// </summary>
    public partial class KsiService
    {
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
            if (_signingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (_signingServiceCredentials == null)
            {
                throw new KsiServiceException("Signing service credentials are missing.");
            }

            if (IsLegacyPduVersion)
            {
                return BeginLegacySign(hash, level, callback, asyncState);
            }

            PduHeader header = new PduHeader(_signingServiceCredentials.LoginId);
            ulong requestId = GenerateRequestId();
            AggregationRequestPayload payload = level == 0 ? new AggregationRequestPayload(requestId, hash) : new AggregationRequestPayload(requestId, hash, level);
            AggregationRequestPdu pdu = new AggregationRequestPdu(header, payload, _macAlgorithm, _signingServiceCredentials.LoginKey);

            Logger.Debug("Begin sign (request id: {0}){1}{2}", requestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _signingServiceProtocol.BeginSign(pdu.Encode(), requestId, callback, asyncState);

            return new CreateSignatureKsiServiceAsyncResult(hash, level, requestId, serviceProtocolAsyncResult, asyncState);
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
            PduHeader header = new PduHeader(_signingServiceCredentials.LoginId);
            ulong requestId = GenerateRequestId();
            LegacyAggregationRequestPayload payload = level == 0
                ? new LegacyAggregationRequestPayload(requestId, hash)
                : new LegacyAggregationRequestPayload(requestId, hash, level);
            LegacyAggregationPdu pdu = new LegacyAggregationPdu(header, payload, LegacyPdu.GetMacTag(_macAlgorithm, _signingServiceCredentials.LoginKey, header, payload));

            Logger.Debug("Begin legacy sign (request id: {0}){1}{2}", requestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _signingServiceProtocol.BeginSign(pdu.Encode(), requestId, callback, asyncState);

            return new CreateSignatureKsiServiceAsyncResult(hash, level, requestId, serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        ///     End create signature (async).
        /// </summary>
        /// <param name="asyncResult">async result status</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature EndSign(IAsyncResult asyncResult)
        {
            if (_signingServiceProtocol == null)
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

            byte[] data = _signingServiceProtocol.EndSign(serviceAsyncResult.ServiceProtocolAsyncResult);
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
                    throw new KsiServiceException("Invalid sign response PDU: null.");
                }

                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.AggregationResponsePdu.TagType)
                {
                    if (IsLegacyPduVersion)
                    {
                        throw new KsiServiceInvalidRequestFormatException(
                            "Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Aggregator.");
                    }

                    pdu = new AggregationResponsePdu(rawTag);
                }
                else if (rawTag.Type == Constants.LegacyAggregationPdu.TagType)
                {
                    if (!IsLegacyPduVersion)
                    {
                        throw new KsiServiceInvalidRequestFormatException(
                            "Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Aggregator.");
                    }

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
                    LegacyAggregationErrorPayload errorPayload = legacyPdu.ErrorPayload as LegacyAggregationErrorPayload;

                    ValidateLegacyResponse(legacyPdu, legacyPayload, errorPayload, serviceAsyncResult.RequestId, _signingServiceCredentials);

                    signature = _ksiSignatureFactory.Create(legacyPayload, serviceAsyncResult.DocumentHash, serviceAsyncResult.Level);
                }
                else
                {
                    AggregationResponsePayload payload = pdu.GetAggregationResponsePayload(serviceAsyncResult.RequestId);
                    AggregationErrorPayload errorPayload = pdu.GetAggregationErrorPayload();

                    ValidateResponse(data, pdu, payload, errorPayload, _signingServiceCredentials);

                    signature = _ksiSignatureFactory.Create(payload, serviceAsyncResult.DocumentHash, serviceAsyncResult.Level);
                }

                Logger.Debug("End sign successful (request id: {0}){1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, signature);

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
        /// Get additional aggregator configuration data (sync)
        /// </summary>
        /// <returns>Aggregator configuration data</returns>
        public AggregatorConfig GetAggregatorConfig()
        {
            return EndGetAggregatorConfig(BeginGetAggregatorConfig(null, null));
        }

        /// <summary>
        /// Begin get additional aggregator configuration data (async)
        /// </summary>
        /// <param name="callback"></param>
        /// <param name="asyncState"></param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetAggregatorConfig(AsyncCallback callback, object asyncState)
        {
            if (IsLegacyPduVersion)
            {
                throw new KsiServiceException("Aggregator config request is not supported using PDU version v1. Configure the SDK to use PDU v2 format for the given Aggregator.");
            }

            if (_signingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (_signingServiceCredentials == null)
            {
                throw new KsiServiceException("Signing service credentials are missing.");
            }

            PduHeader header = new PduHeader(_signingServiceCredentials.LoginId);
            AggregatorConfigRequestPayload payload = new AggregatorConfigRequestPayload();
            AggregationRequestPdu pdu = new AggregationRequestPdu(header, payload, _macAlgorithm, _signingServiceCredentials.LoginKey);

            ulong requestId = GenerateRequestId();

            Logger.Debug("Begin get aggregator config (request id: {0}){1}{2}", requestId, Environment.NewLine, pdu);

            IAsyncResult serviceProtocolAsyncResult = _signingServiceProtocol.BeginSign(pdu.Encode(), requestId, callback, asyncState);

            return new AggregatorConfigKsiServiceAsyncResult(requestId, serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        /// End get additional aggregator configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Aggregator configuration data</returns>
        public AggregatorConfig EndGetAggregatorConfig(IAsyncResult asyncResult)
        {
            if (_signingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (asyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult: null.");
            }

            AggregatorConfigKsiServiceAsyncResult serviceAsyncResult = asyncResult as AggregatorConfigKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult, could not cast to correct object.");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _signingServiceProtocol.EndSign(serviceAsyncResult.ServiceProtocolAsyncResult);

            AggregationResponsePdu pdu = null;

            try
            {
                if (data == null)
                {
                    throw new KsiServiceException("Invalid aggregator config response PDU: null.");
                }

                RawTag rawTag;

                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.LegacyAggregationPdu.TagType)
                {
                    throw new KsiServiceInvalidRequestFormatException("Received PDU v1 response to PDU v2 request.");
                }

                pdu = new AggregationResponsePdu(rawTag);

                AggregatorConfigResponsePayload payload = pdu.GetAggregatorConfigResponsePayload();
                AggregationErrorPayload errorPayload = pdu.GetAggregationErrorPayload();

                ValidateResponse(data, pdu, payload, errorPayload, _signingServiceCredentials);

                return new AggregatorConfig(payload);
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiServiceException("Could not parse response message: " + Base16.Encode(data), e);
                Logger.Warn("End aggregator config request failed (request id: {0}): {1}", serviceAsyncResult.RequestId, ksiException);
                throw ksiException;
            }
            catch (KsiException e)
            {
                Logger.Warn("End aggregator config request failed (request id: {0}): {1}{2}{3}", serviceAsyncResult.RequestId, e, Environment.NewLine, pdu);

                throw;
            }
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

        private class AggregatorConfigKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public AggregatorConfigKsiServiceAsyncResult(ulong requestId, IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
                RequestId = requestId;
            }

            public ulong RequestId { get; }
        }
    }
}