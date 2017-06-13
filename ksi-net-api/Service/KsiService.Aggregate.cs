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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service.
    /// </summary>
    public partial class KsiService
    {
        private KsiServiceResponseParser _signRequestResponseParser;
        private KsiServiceResponseParser _aggregatorConfigRequestResponseParser;

        /// <summary>
        ///     Create signature with given data hash (sync).
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature Sign(DataHash hash, uint level = 0)
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
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }

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
            AggregationRequestPdu pdu = new AggregationRequestPdu(header, payload, _signingMacAlgorithm, _signingServiceCredentials.LoginKey);

            Logger.Debug("Begin sign (request id: {0}){1}{2}", payload.RequestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _signingServiceProtocol.BeginSign(pdu.Encode(), payload.RequestId, callback, asyncState);

            return new CreateSignatureKsiServiceAsyncResult(payload, serviceProtocolAsyncResult, asyncState);
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
            LegacyAggregationPdu pdu = new LegacyAggregationPdu(header, payload, LegacyPdu.GetMacTag(_signingMacAlgorithm, _signingServiceCredentials.LoginKey, header, payload));

            Logger.Debug("Begin legacy sign (request id: {0}){1}{2}", payload.RequestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _signingServiceProtocol.BeginSign(pdu.Encode(), payload.RequestId, callback, asyncState);

            return new CreateSignatureKsiServiceAsyncResult(payload, serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        ///     End create signature (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>KSI signature</returns>
        public IKsiSignature EndSign(IAsyncResult asyncResult)
        {
            SignRequestResponsePayload reponsePayload = GetSignResponsePayload(asyncResult);

            CreateSignatureKsiServiceAsyncResult serviceAsyncResult = asyncResult as CreateSignatureKsiServiceAsyncResult;

            IKsiSignature signature;
            LegacyAggregationResponsePayload legacyPayload = reponsePayload as LegacyAggregationResponsePayload;
            AggregationResponsePayload payload = reponsePayload as AggregationResponsePayload;

            if (legacyPayload != null)
            {
                signature = _ksiSignatureFactory.Create(legacyPayload, serviceAsyncResult.DocumentHash, serviceAsyncResult.Level);
            }
            else
            {
                signature = _ksiSignatureFactory.Create(payload, serviceAsyncResult.DocumentHash, serviceAsyncResult.Level);
            }

            Logger.Debug("End sign successful (request id: {0}){1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, signature);

            return signature;
        }

        /// <summary>
        /// Get sign request response payload (async).
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>Request response payload</returns>
        public SignRequestResponsePayload GetSignResponsePayload(IAsyncResult asyncResult)
        {
            if (_signingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
            }

            if (asyncResult == null)
            {
                throw new ArgumentNullException(nameof(asyncResult));
            }

            CreateSignatureKsiServiceAsyncResult serviceAsyncResult = asyncResult as CreateSignatureKsiServiceAsyncResult;

            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid " + nameof(asyncResult) + ", could not cast to correct object.");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _signingServiceProtocol.EndSign(serviceAsyncResult.ServiceProtocolAsyncResult);
            PduPayload payload = SignRequestResponseParser.Parse(data, serviceAsyncResult.RequestId);
            SignRequestResponsePayload signResponsePayload = payload as SignRequestResponsePayload;

            if (signResponsePayload == null)
            {
                Logger.Warn("Sign request failed. Invalid response payload.{0}Payload:{0}{1}", Environment.NewLine, payload);
                throw new KsiServiceException("Invalid sign response payload. Type: " + payload.Type);
            }

            return signResponsePayload;
        }

        private KsiServiceResponseParser SignRequestResponseParser
        {
            get
            {
                if (_signRequestResponseParser == null)
                {
                    _signRequestResponseParser = new KsiServiceResponseParser(PduVersion, KsiServiceRequestType.Sign, _signingMacAlgorithm,
                        _signingServiceCredentials.LoginKey);
                }

                return _signRequestResponseParser;
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
            AggregationRequestPdu pdu = new AggregationRequestPdu(header, payload, _signingMacAlgorithm, _signingServiceCredentials.LoginKey);

            ulong requestId = GenerateRequestId();

            Logger.Debug("Begin get aggregator config (request id: {0}){1}{2}", requestId, Environment.NewLine, pdu);

            IAsyncResult serviceProtocolAsyncResult = _signingServiceProtocol.BeginGetAggregatorConfig(pdu.Encode(), requestId, callback, asyncState);

            return new AggregatorConfigKsiServiceAsyncResult(serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        /// End get additional aggregator configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Aggregator configuration data</returns>
        public AggregatorConfig EndGetAggregatorConfig(IAsyncResult asyncResult)
        {
            if (asyncResult == null)
            {
                throw new ArgumentNullException(nameof(asyncResult));
            }

            if (_signingServiceProtocol == null)
            {
                throw new KsiServiceException("Signing service protocol is missing from service.");
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
            PduPayload payload = AggregatorConfigRequestResponseParser.Parse(data);
            AggregatorConfigResponsePayload configResponsePayload = payload as AggregatorConfigResponsePayload;

            if (configResponsePayload == null)
            {
                Logger.Warn("Aggregator config request failed. Invalid response payload.{0}Payload:{0}{1}", Environment.NewLine, payload);
                throw new KsiServiceException("Invalid config response payload. Type: " + payload.Type);
            }

            return new AggregatorConfig(configResponsePayload);
        }

        private KsiServiceResponseParser AggregatorConfigRequestResponseParser
        {
            get
            {
                if (_aggregatorConfigRequestResponseParser == null)
                {
                    _aggregatorConfigRequestResponseParser = new KsiServiceResponseParser(PduVersion, KsiServiceRequestType.AggregatorConfig,
                        _signingMacAlgorithm, _signingServiceCredentials.LoginKey);
                }

                return _aggregatorConfigRequestResponseParser;
            }
        }

        /// <summary>
        ///     Create signature KSI service async result.
        /// </summary>
        private class CreateSignatureKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            private readonly AggregationRequestPayload _payload;
            private readonly LegacyAggregationRequestPayload _legacyPayload;

            public CreateSignatureKsiServiceAsyncResult(AggregationRequestPayload payload, IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
                if (payload == null)
                {
                    throw new ArgumentNullException(nameof(payload));
                }

                _payload = payload;
            }

            public CreateSignatureKsiServiceAsyncResult(LegacyAggregationRequestPayload legacyPayload, IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
                if (legacyPayload == null)
                {
                    throw new ArgumentNullException(nameof(legacyPayload));
                }

                _legacyPayload = legacyPayload;
            }

            public ulong RequestId => _payload?.RequestId ?? _legacyPayload.RequestId;

            public uint? Level => (uint?)(_payload != null ? _payload?.RequestLevel : _legacyPayload.RequestLevel);

            public DataHash DocumentHash => _payload?.RequestHash ?? _legacyPayload.RequestHash;
        }

        private class AggregatorConfigKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public AggregatorConfigKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
            }
        }
    }
}