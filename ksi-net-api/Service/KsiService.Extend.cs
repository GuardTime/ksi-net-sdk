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
            if (IsLegacyPduVersion)
            {
                return BeginLegacyExtend(aggregationTime, null, null);
            }
            return BeginExtend(new ExtendRequestPayload(GenerateRequestId(), aggregationTime), callback, asyncState);
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
            if (IsLegacyPduVersion)
            {
                return BeginLegacyExtend(aggregationTime, publicationTime, null, null);
            }

            return BeginExtend(new ExtendRequestPayload(GenerateRequestId(), aggregationTime, publicationTime), callback, asyncState);
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
                    throw new KsiServiceException("Invalid extend response PDU: null.");
                }

                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.ExtendResponsePdu.TagType)
                {
                    if (IsLegacyPduVersion)
                    {
                        throw new InvalidRequestFormatException("Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Extender.");
                    }

                    pdu = new ExtendResponsePdu(rawTag);
                }
                else if (rawTag.Type == Constants.LegacyExtendPdu.TagType)
                {
                    if (!IsLegacyPduVersion)
                    {
                        throw new InvalidRequestFormatException("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Extender.");
                    }

                    legacyPdu = new LegacyExtendPdu(rawTag);
                }
                else
                {
                    throw new KsiServiceException("Unknown response PDU tag type: " + rawTag.Type.ToString("X"));
                }

                CalendarHashChain calendarHashChain;

                if (legacyPdu != null)
                {
                    LegacyExtendResponsePayload legacyPayload = legacyPdu.Payload as LegacyExtendResponsePayload;
                    LegacyExtendErrorPayload errorPayload = legacyPdu.Payload as LegacyExtendErrorPayload;

                    ValidateLegacyResponse(legacyPdu, legacyPayload, errorPayload, serviceAsyncResult.RequestId, _extendingServiceCredentials);

                    calendarHashChain = legacyPayload.CalendarHashChain;
                }
                else
                {
                    ExtendResponsePayload payload = pdu.GetExtendResponsePayload(serviceAsyncResult.RequestId);
                    ExtendErrorPayload errorPayload = pdu.GetExtendErrorPayload();

                    ValidateResponse(pdu, payload, errorPayload, _extendingServiceCredentials);

                    calendarHashChain = payload.CalendarHashChain;
                }

                if (calendarHashChain == null)
                {
                    throw new KsiServiceException("No calendar hash chain in payload.");
                }

                Logger.Debug("End extend successful (request id: {0}) {1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, legacyPdu);

                return calendarHashChain;
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiServiceException("Could not parse extend response message: " + Base16.Encode(data), e);
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
        /// <param name="callback"></param>
        /// <param name="asyncState"></param>
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

            KsiPduHeader header = new KsiPduHeader(_extendingServiceCredentials.LoginId);
            ExtenderConfigRequestPayload payload = new ExtenderConfigRequestPayload();
            ExtendRequestPdu pdu = new ExtendRequestPdu(header, payload, _hmacAlgorithm, _extendingServiceCredentials.LoginKey);

            ulong requestId = GenerateRequestId();

            Logger.Debug("Begin get extender config (request id: {0}){1}{2}", requestId, Environment.NewLine, pdu);

            IAsyncResult serviceProtocolAsyncResult = _extendingServiceProtocol.BeginExtend(pdu.Encode(), requestId, callback, asyncState);

            return new ExtenderConfigKsiServiceAsyncResult(requestId, serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        /// End get additional extender configuration data (async)
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns>Extender configuration data</returns>
        public ExtenderConfig EndGetExtenderConfig(IAsyncResult asyncResult)
        {
            if (_extendingServiceProtocol == null)
            {
                throw new KsiServiceException("Extending service protocol is missing from service.");
            }

            if (asyncResult == null)
            {
                throw new KsiException("Invalid IAsyncResult: null.");
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

            ExtendResponsePdu pdu = null;

            try
            {
                if (data == null)
                {
                    throw new KsiException("Invalid extender config response payload: null.");
                }

                RawTag rawTag;

                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == Constants.LegacyExtendPdu.TagType)
                {
                    throw new InvalidRequestFormatException("Received PDU v1 response to PDU v2 request.");
                }

                pdu = new ExtendResponsePdu(rawTag);

                ExtenderConfigResponsePayload payload = pdu.GetExtenderConfigResponsePayload();
                ExtendErrorPayload errorPayload = pdu.GetExtendErrorPayload();

                ValidateResponse(pdu, payload, errorPayload, _extendingServiceCredentials);

                Logger.Debug("End get extender config successful (request id: {0}){1}{2}", serviceAsyncResult.RequestId, Environment.NewLine, pdu);

                return new ExtenderConfig(payload);
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiException("Could not parse extender config response message: " + Base16.Encode(data), e);
                Logger.Warn("End extender config request failed (request id: {0}): {1}", serviceAsyncResult.RequestId, ksiException);
                throw ksiException;
            }
            catch (KsiException e)
            {
                Logger.Warn("End extender config request failed (request id: {0}): {1}{2}{3}", serviceAsyncResult.RequestId, e, Environment.NewLine, pdu);

                throw;
            }
        }

        private class ExtenderConfigKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public ExtenderConfigKsiServiceAsyncResult(ulong requestId, IAsyncResult serviceProtocolAsyncResult, object asyncState)
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
    }
}