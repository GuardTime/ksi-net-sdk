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
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service.
    /// </summary>
    public partial class KsiService
    {
        private KsiServiceResponseParser _extendRequestResponseParser;
        private KsiServiceResponseParser _extenderConfigRequestResponseParser;

        /// <summary>
        ///     Extend to latest publication (sync).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain Extend(ulong aggregationTime)
        {
            return EndExtend(BeginExtend(aggregationTime, null, null));
        }

        /// <summary>
        ///     Extend to given publication (sync).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <returns>extended calendar hash chain</returns>
        public CalendarHashChain Extend(ulong aggregationTime, ulong publicationTime)
        {
            return EndExtend(BeginExtend(aggregationTime, publicationTime, null, null));
        }

        /// <summary>
        ///     Begin extend to latest publication (async).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtend(ulong aggregationTime, AsyncCallback callback, object asyncState)
        {
            if (IsLegacyPduVersion)
            {
                return BeginLegacyExtend(aggregationTime, null, null);
            }

            return BeginExtend(new ExtendRequestPayload(GenerateRequestId(), aggregationTime), callback, asyncState);
        }

        /// <summary>
        ///     Begin extend to given publication (async).
        /// </summary>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtend(ulong aggregationTime, ulong publicationTime, AsyncCallback callback,
                                        object asyncState)
        {
            if (IsLegacyPduVersion)
            {
                return BeginLegacyExtend(aggregationTime, publicationTime, null, null);
            }

            return BeginExtend(new ExtendRequestPayload(GenerateRequestId(), aggregationTime, publicationTime), callback, asyncState);
        }

        /// <summary>
        ///     Begin extend.
        /// </summary>
        /// <param name="payload">extend request payload</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">callback async state object</param>
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

            PduHeader header = new PduHeader(_extendingServiceCredentials.LoginId);
            ExtendRequestPdu pdu = new ExtendRequestPdu(header, payload, _extendingMacAlgorithm, _extendingServiceCredentials.LoginKey);

            Logger.Debug("Begin extend. (request id: {0}){1}{2}", payload.RequestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _extendingServiceProtocol.BeginExtend(pdu.Encode(), payload.RequestId, callback, asyncState);

            return new ExtendKsiServiceAsyncResult(payload.RequestId, serviceProtocolAsyncResult, asyncState);
        }

        [Obsolete]
        private IAsyncResult BeginLegacyExtend(ulong aggregationTime, AsyncCallback callback, object asyncState)
        {
            return BeginLegacyExtend(new LegacyExtendRequestPayload(GenerateRequestId(), aggregationTime), callback, asyncState);
        }

        [Obsolete]
        private IAsyncResult BeginLegacyExtend(ulong aggregationTime, ulong publicationTime, AsyncCallback callback,
                                               object asyncState)
        {
            return BeginLegacyExtend(new LegacyExtendRequestPayload(GenerateRequestId(), aggregationTime, publicationTime), callback, asyncState);
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

            PduHeader header = new PduHeader(_extendingServiceCredentials.LoginId);
            LegacyExtendPdu pdu = new LegacyExtendPdu(header, payload, LegacyPdu.GetMacTag(_extendingMacAlgorithm, _extendingServiceCredentials.LoginKey, header, payload));

            Logger.Debug("Begin legacy extend. (request id: {0}){1}{2}", payload.RequestId, Environment.NewLine, pdu);
            IAsyncResult serviceProtocolAsyncResult = _extendingServiceProtocol.BeginExtend(pdu.Encode(), payload.RequestId, callback, asyncState);

            return new ExtendKsiServiceAsyncResult(payload.RequestId, serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        ///     End extend (async).
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
                throw new ArgumentNullException(nameof(asyncResult));
            }

            ExtendKsiServiceAsyncResult serviceAsyncResult = asyncResult as ExtendKsiServiceAsyncResult;

            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid " + nameof(asyncResult) + ", could not cast to correct object.");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _extendingServiceProtocol.EndExtend(serviceAsyncResult.ServiceProtocolAsyncResult);
            PduPayload payload = ExtendRequestResponseParser.Parse(data, serviceAsyncResult.RequestId);

            if (IsLegacyPduVersion)
            {
                LegacyExtendResponsePayload legacyResponsePayload = payload as LegacyExtendResponsePayload;

                if (legacyResponsePayload == null)
                {
                    Logger.Warn("Extend request failed. Invalid response payload.{0}Payload:{0}{1}", Environment.NewLine, payload);
                    throw new KsiServiceException("Invalid extend response payload. Type: " + payload.Type);
                }

                return legacyResponsePayload.CalendarHashChain;
            }
            else

            {
                ExtendResponsePayload responsePayload = payload as ExtendResponsePayload;

                if (responsePayload == null)
                {
                    Logger.Warn("Extend request failed. Invalid response payload.{0}Payload:{0}{1}", Environment.NewLine, payload);
                    throw new KsiServiceException("Invalid extend response payload. Type: " + payload.Type);
                }

                return responsePayload.CalendarHashChain;
            }
        }

        private KsiServiceResponseParser ExtendRequestResponseParser
        {
            get
            {
                if (_extendRequestResponseParser == null)
                {
                    _extendRequestResponseParser = new KsiServiceResponseParser(PduVersion, KsiServiceRequestType.Extend, _extendingMacAlgorithm,
                        _extendingServiceCredentials.LoginKey);
                    _extendRequestResponseParser.ExtenderConfigChanged += RequestResponseParser_ExtenderConfigChanged;
                }

                return _extendRequestResponseParser;
            }
        }

        private void RequestResponseParser_ExtenderConfigChanged(object sender, ExtenderConfigChangedEventArgs e)
        {
            ExtenderConfigChanged?.Invoke(this, new ExtenderConfigChangedEventArgs(e.ExtenderConfig, this));
        }

        /// <summary>
        /// Get additional extender configuration data (sync)
        /// </summary>
        /// <returns>Extender configuration data</returns>
        public ExtenderConfig GetExtenderConfig()
        {
            return EndGetExtenderConfig(BeginGetExtenderConfig(null, null));
        }

        /// <summary>
        /// Begin get additional extender configuration data (async)
        /// </summary>
        /// <param name="callback">callback when extnder configuration request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetExtenderConfig(AsyncCallback callback, object asyncState)
        {
            if (IsLegacyPduVersion)
            {
                throw new KsiServiceException("Extender config request is not supported using PDU version v1. Configure the SDK to use PDU v2 format for the given Extender.");
            }

            if (_extendingServiceProtocol == null)
            {
                throw new KsiServiceException("Extending service protocol is missing from service.");
            }

            if (_extendingServiceCredentials == null)
            {
                throw new KsiServiceException("Extending service credentials are missing.");
            }

            PduHeader header = new PduHeader(_extendingServiceCredentials.LoginId);
            ExtenderConfigRequestPayload payload = new ExtenderConfigRequestPayload();
            ExtendRequestPdu pdu = new ExtendRequestPdu(header, payload, _extendingMacAlgorithm, _extendingServiceCredentials.LoginKey);

            ulong requestId = GenerateRequestId();

            Logger.Debug("Begin get extender config (request id: {0}){1}{2}", requestId, Environment.NewLine, pdu);

            IAsyncResult serviceProtocolAsyncResult = _extendingServiceProtocol.BeginExtend(pdu.Encode(), requestId, callback, asyncState);

            return new ExtenderConfigKsiServiceAsyncResult(serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        /// End get additional extender configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Extender configuration data</returns>
        public ExtenderConfig EndGetExtenderConfig(IAsyncResult asyncResult)
        {
            if (asyncResult == null)
            {
                throw new ArgumentNullException(nameof(asyncResult));
            }

            if (_extendingServiceProtocol == null)
            {
                throw new KsiServiceException("Extending service protocol is missing from service.");
            }

            ExtenderConfigKsiServiceAsyncResult serviceAsyncResult = asyncResult as ExtenderConfigKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                throw new KsiServiceException("Invalid IAsyncResult, could not cast to correct object.");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _extendingServiceProtocol.EndExtend(serviceAsyncResult.ServiceProtocolAsyncResult);
            PduPayload payload = ExtenderConfigRequestResponseParser.Parse(data);
            ExtenderConfigResponsePayload configResponsePayload = payload as ExtenderConfigResponsePayload;

            if (configResponsePayload == null)
            {
                Logger.Warn("Extender config request failed. Invalid response payload.{0}Payload:{0}{1}", Environment.NewLine, payload);
                throw new KsiServiceException("Invalid config response payload. Type: " + payload.Type);
            }

            return new ExtenderConfig(configResponsePayload);
        }

        private KsiServiceResponseParser ExtenderConfigRequestResponseParser
        {
            get
            {
                if (_extenderConfigRequestResponseParser == null)
                {
                    _extenderConfigRequestResponseParser = new KsiServiceResponseParser(PduVersion, KsiServiceRequestType.ExtenderConfig,
                        _extendingMacAlgorithm, _extendingServiceCredentials.LoginKey);
                    _extenderConfigRequestResponseParser.ExtenderConfigChanged += RequestResponseParser_ExtenderConfigChanged;
                }

                return _extenderConfigRequestResponseParser;
            }
        }

        private class ExtenderConfigKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public ExtenderConfigKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
            }
        }

        /// <summary>
        ///     Extend KSI service async result.
        /// </summary>
        private class ExtendKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public ExtendKsiServiceAsyncResult(ulong requestId, IAsyncResult serviceProtocolAsyncResult, object asyncState)
                : base(serviceProtocolAsyncResult, asyncState)
            {
                RequestId = requestId;
            }

            public ulong RequestId { get; }
        }
    }
}