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
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Class for parsing KSI service response.
    /// </summary>
    public class KsiServiceResponseParser
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private readonly PduVersion _pduVersion;
        private readonly KsiServiceRequestType _requestType;
        private readonly HashAlgorithm _macAlgorithm;
        private readonly byte[] _macKey;
        private AggregatorConfig _currentAggregatorConfig;
        private ExtenderConfig _currentExtenderConfig;

        /// <summary>
        /// Aggregator configuration changed event
        /// </summary>
        public event EventHandler<AggregatorConfigChangedEventArgs> AggregatorConfigChanged;

        /// <summary>
        /// Extender configuration changed event
        /// </summary>
        public event EventHandler<ExtenderConfigChangedEventArgs> ExtenderConfigChanged;

        /// <summary>
        /// Create new KSI service reponse parser. 
        /// </summary>
        /// <param name="pduVersion">PDU version</param>
        /// <param name="requestType">Request type of the response to be parsed</param>
        /// <param name="macAlgorithm">MAC calculation algorithm</param>
        /// <param name="macKey">MAC calculation key</param>
        public KsiServiceResponseParser(PduVersion pduVersion, KsiServiceRequestType requestType, HashAlgorithm macAlgorithm, byte[] macKey)
        {
            _pduVersion = pduVersion;
            _requestType = requestType;
            _macAlgorithm = macAlgorithm;
            _macKey = macKey;
        }

        /// <summary>
        /// Parse KSI service response.
        /// </summary>
        /// <param name="data">Response byte array</param>
        /// <param name="requestId">Request ID</param>
        /// <returns></returns>
        public PduPayload Parse(byte[] data, ulong? requestId = null)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            RawTag rawTag = null;
            Pdu pdu = null;
            LegacyPdu legacyPdu = null;

            try
            {
                using (TlvReader reader = new TlvReader(new MemoryStream(data)))
                {
                    rawTag = new RawTag(reader.ReadTag());
                }

                if (rawTag.Type == GetPduTagType(false))
                {
                    if (_pduVersion == PduVersion.v1)
                    {
                        throw new KsiServiceUnexpectedResponseFormatException("Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format.");
                    }

                    pdu = GetPdu(rawTag);
                }
                else if (rawTag.Type == GetPduTagType(true))
                {
                    if (_pduVersion == PduVersion.v2)
                    {
                        if (!IsLegacyRequestSupported())
                        {
                            throw new KsiServiceUnexpectedResponseFormatException("Received PDU v1 response to PDU v2 request.");
                        }

                        throw new KsiServiceUnexpectedResponseFormatException("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format.");
                    }

                    legacyPdu = GetLegacyPdu(rawTag);
                }
                else
                {
                    throw new KsiServiceException("Unknown response PDU tag type: " + rawTag.Type.ToString("X"));
                }

                if (legacyPdu != null)
                {
                    return GetLegacyResponsePayload(legacyPdu, requestId);
                }
                else
                {
                    CheckAggregatorConfigChange(pdu);
                    CheckExtenderConfigChange(pdu);

                    return GetResponsePayload(data, pdu, requestId);
                }
            }
            catch (TlvException e)
            {
                KsiException ksiException = new KsiServiceException("Could not parse response message: " + Base16.Encode(data), e);
                if (requestId.HasValue)
                {
                    Logger.Warn("Request failed (request id: {0}): {1}", requestId, ksiException);
                }
                else
                {
                    Logger.Warn("Request failed: {0}", ksiException);
                }
                throw ksiException;
            }
            catch (KsiException e)
            {
                if (requestId.HasValue)
                {
                    Logger.Warn("Request failed (request id: {0}){1}{2}{1}PDU:{1}{3}", requestId, Environment.NewLine, e, legacyPdu ?? pdu ?? (ITlvTag)rawTag);
                }
                else
                {
                    Logger.Warn("Request failed.{0}{1}{0}PDU:{0}{2}", Environment.NewLine, e, legacyPdu ?? pdu ?? (ITlvTag)rawTag);
                }

                throw;
            }
        }

        private void CheckAggregatorConfigChange(Pdu pdu)
        {
            if (AggregatorConfigChanged != null)
            {
                AggregatorConfigResponsePayload configPayload = GetPayload(pdu, Constants.AggregatorConfigResponsePayload.TagType, null) as AggregatorConfigResponsePayload;
                if (configPayload != null)
                {
                    AggregatorConfig aggregatorConfig = new AggregatorConfig(configPayload);

                    if (_currentAggregatorConfig == null || !_currentAggregatorConfig.Equals(aggregatorConfig))
                    {
                        _currentAggregatorConfig = aggregatorConfig;
                        AggregatorConfigChanged.BeginInvoke(this, new AggregatorConfigChangedEventArgs(_currentAggregatorConfig), null, null);
                    }
                }
            }
        }

        private void CheckExtenderConfigChange(Pdu pdu)
        {
            if (ExtenderConfigChanged != null)
            {
                ExtenderConfigResponsePayload configPayload = GetPayload(pdu, Constants.ExtenderConfigResponsePayload.TagType, null) as ExtenderConfigResponsePayload;
                if (configPayload != null)
                {
                    ExtenderConfig extenderConfig = new ExtenderConfig(configPayload);

                    if (_currentExtenderConfig == null || !_currentExtenderConfig.Equals(extenderConfig))
                    {
                        _currentExtenderConfig = extenderConfig;
                        ExtenderConfigChanged.BeginInvoke(this, new ExtenderConfigChangedEventArgs(_currentExtenderConfig), null, null);
                    }
                }
            }
        }

        /// <summary>
        /// Returns true if request was available already in PDU version v1.
        /// </summary>
        /// <returns></returns>
        private bool IsLegacyRequestSupported()
        {
            switch (_requestType)
            {
                case KsiServiceRequestType.Sign:
                case KsiServiceRequestType.Extend:
                    return true;
                case KsiServiceRequestType.AggregatorConfig:
                case KsiServiceRequestType.ExtenderConfig:
                    return false;
                default:
                    throw new KsiServiceException("Unhandled request type: " + _requestType);
            }
        }

        /// <summary>
        /// Get expected PDU tag type.
        /// </summary>
        /// <param name="isLegacy"></param>
        /// <returns></returns>
        private uint GetPduTagType(bool isLegacy)
        {
            switch (_requestType)
            {
                case KsiServiceRequestType.Sign:
                case KsiServiceRequestType.AggregatorConfig:
                    if (isLegacy)
                    {
                        return Constants.LegacyAggregationPdu.TagType;
                    }
                    return Constants.AggregationResponsePdu.TagType;
                case KsiServiceRequestType.Extend:
                case KsiServiceRequestType.ExtenderConfig:
                    if (isLegacy)
                    {
                        return Constants.LegacyExtendPdu.TagType;
                    }
                    return Constants.ExtendResponsePdu.TagType;
                default:
                    throw new KsiServiceException("Unhandled request type: " + _requestType);
            }
        }

        /// <summary>
        /// Get expected payload tag type
        /// </summary>
        /// <param name="isLegacy"></param>
        /// <returns></returns>
        private uint GetPayloadTagType(bool isLegacy)
        {
            switch (_requestType)
            {
                case KsiServiceRequestType.Sign:
                    if (isLegacy)
                    {
                        return Constants.AggregationResponsePayload.LegacyTagType;
                    }
                    return Constants.AggregationResponsePayload.TagType;
                case KsiServiceRequestType.AggregatorConfig:
                    if (!isLegacy)
                    {
                        return Constants.AggregatorConfigResponsePayload.TagType;
                    }
                    break;
                case KsiServiceRequestType.Extend:
                    if (isLegacy)
                    {
                        return Constants.ExtendResponsePayload.LegacyTagType;
                    }
                    return Constants.ExtendResponsePayload.TagType;
                case KsiServiceRequestType.ExtenderConfig:
                    if (!isLegacy)
                    {
                        return Constants.ExtenderConfigResponsePayload.TagType;
                    }
                    break;
            }

            throw new KsiServiceException("Unhandled request type: " + _requestType);
        }

        /// <summary>
        /// Get list of additionally allowed payload types (eg. pushed payload types)
        /// </summary>
        /// <returns></returns>
        private uint[] GetAdditionallyAllowedPayloadTagTypes()
        {
            switch (_requestType)
            {
                case KsiServiceRequestType.Sign:
                    return new uint[] { Constants.AggregatorConfigResponsePayload.TagType, Constants.AggregationAcknowledgmentResponsePayload.TagType };
                case KsiServiceRequestType.AggregatorConfig:
                    return new uint[] { Constants.AggregationAcknowledgmentResponsePayload.TagType };
                case KsiServiceRequestType.Extend:
                    return new uint[] { Constants.ExtenderConfigResponsePayload.TagType };
                case KsiServiceRequestType.ExtenderConfig:
                    return null;
                default:
                    throw new KsiServiceException("Unhandled request type: " + _requestType);
            }
        }

        /// <summary>
        /// Get PDU tag from raw tag.
        /// </summary>
        /// <param name="rawTag"></param>
        /// <returns></returns>
        private Pdu GetPdu(RawTag rawTag)
        {
            switch (GetPduTagType(false))
            {
                case Constants.AggregationResponsePdu.TagType:
                    return new AggregationResponsePdu(rawTag);
                case Constants.ExtendResponsePdu.TagType:
                    return new ExtendResponsePdu(rawTag);
                default:
                    throw new KsiServiceException("Unhandled tag type: " + GetPduTagType(false));
            }
        }

        /// <summary>
        /// Get legacy PDU tag from raw tag.
        /// </summary>
        /// <param name="rawTag"></param>
        /// <returns></returns>
        private LegacyPdu GetLegacyPdu(RawTag rawTag)
        {
            switch (GetPduTagType(true))
            {
                case Constants.LegacyAggregationPdu.TagType:
                    return new LegacyAggregationPdu(rawTag);
                case Constants.LegacyExtendPdu.TagType:
                    return new LegacyExtendPdu(rawTag);
                default:
                    throw new KsiServiceException("Unhandled tag type: " + GetPduTagType(true));
            }
        }

        /// <summary>
        /// Log unexpected payloads warning.
        /// </summary>
        /// <param name="pdu"></param>
        private static void LogUnexpectedPayloads(ITlvTag pdu)
        {
            Logger.Warn(string.Format("Unexpected response payloads!{0}PDU:{0}{1}", Environment.NewLine, pdu));
        }

        /// <summary>
        /// Get response payload.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="pdu"></param>
        /// <param name="requestId"></param>
        /// <returns></returns>
        private PduPayload GetResponsePayload(byte[] data, Pdu pdu, ulong? requestId)
        {
            PduPayload payload = GetPayload(pdu, GetPayloadTagType(false), requestId);
            ErrorPayload errorPayload = pdu.ErrorPayload;

            if (payload == null && errorPayload == null)
            {
                throw new KsiServiceException("Invalid response PDU. Could not find a valid payload. PDU: " + pdu);
            }

            if (errorPayload != null)
            {
                // There should be only one payload if an error payload exists. If not then write log.
                if (pdu.Payloads.Count > 1)
                {
                    LogUnexpectedPayloads(pdu);
                }

                throw new KsiServiceException(FormatServerErrorStatus(errorPayload.Status, errorPayload.ErrorMessage));
            }

            CheckMacAlgorithm(pdu.Mac, _macAlgorithm);

            if (!Pdu.ValidateMac(data, pdu.Mac, _macKey))
            {
                throw new KsiServiceException("Invalid MAC in response PDU.");
            }

            if (requestId.HasValue)
            {
                RequestResponsePayload requestResponsePayload = payload as RequestResponsePayload;

                if (requestResponsePayload == null)
                {
                    throw new KsiServiceException("Cannot get request ID from payload.");
                }

                if (requestResponsePayload.RequestId != requestId)
                {
                    throw new KsiServiceException("Unknown request ID: " + requestResponsePayload.RequestId);
                }

                if (requestResponsePayload.Status != 0)
                {
                    throw new KsiServiceException(FormatServerErrorStatus(requestResponsePayload.Status, requestResponsePayload.ErrorMessage));
                }
            }

            if (HasUnexpectedPayload(pdu, payload, GetAdditionallyAllowedPayloadTagTypes()))
            {
                LogUnexpectedPayloads(pdu);
            }

            return payload;
        }

        /// <summary>
        /// GEt legacy response payload.
        /// </summary>
        /// <param name="pdu"></param>
        /// <param name="requestId"></param>
        /// <returns></returns>
        private PduPayload GetLegacyResponsePayload(LegacyPdu pdu, ulong? requestId)
        {
            PduPayload payload = pdu.Payload;

            if (payload == null && pdu.ErrorPayload == null)
            {
                throw new KsiServiceException("Invalid response payload: null.");
            }

            if (payload != null && payload.Type != GetPayloadTagType(true))
            {
                throw new KsiServiceException("Unexpected response payload tag type. Type: " + payload.Type + "; Expected type: " + GetPayloadTagType(true));
            }

            if (pdu.ErrorPayload != null)
            {
                if (payload != null)
                {
                    // If error payload exists then Payload should be null. Log it.
                    LogUnexpectedPayloads(pdu);
                }
                throw new KsiServiceException(FormatServerErrorStatus(pdu.ErrorPayload.Status, pdu.ErrorPayload.ErrorMessage));
            }

            CheckMacAlgorithm(pdu.Mac, _macAlgorithm);

            if (!LegacyPdu.ValidateMac(pdu.Encode(), pdu.Mac, _macKey))
            {
                throw new KsiServiceException("Invalid MAC in response PDU.");
            }

            if (requestId.HasValue)
            {
                RequestResponsePayload requestResponsePayload = payload as RequestResponsePayload;

                if (requestResponsePayload == null)
                {
                    throw new KsiServiceException("Cannot get request ID from payload. Payload type: " + payload.GetType());
                }

                if (requestResponsePayload.RequestId != requestId)
                {
                    throw new KsiServiceException("Unknown request ID: " + requestResponsePayload.RequestId);
                }
            }

            ResponsePayload responsePayload = payload as ResponsePayload;

            if (responsePayload == null)
            {
                throw new KsiServiceException("Cannot get status from payload. Payload type: " + payload.GetType());
            }

            if (responsePayload.Status != 0)
            {
                throw new KsiServiceException(FormatServerErrorStatus(responsePayload.Status, responsePayload.ErrorMessage));
            }

            return payload;
        }

        /// <summary>
        /// Get payoad from PDU by tag type and request ID.
        /// </summary>
        /// <param name="pdu"></param>
        /// <param name="tagType"></param>
        /// <param name="requestId"></param>
        /// <returns></returns>
        private static PduPayload GetPayload(Pdu pdu, uint tagType, ulong? requestId)
        {
            foreach (PduPayload payload in pdu.Payloads)
            {
                if (payload.Type == tagType)
                {
                    if (!requestId.HasValue)
                    {
                        return payload;
                    }

                    RequestResponsePayload responsePayload = payload as RequestResponsePayload;

                    if (responsePayload != null && responsePayload.RequestId == requestId)
                    {
                        return payload;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Returns true if there are payloads in PDU that should not be there (not expected and not allowed).
        /// </summary>
        /// <param name="pdu">PDU to search unexpected payloads</param>
        /// <param name="expectedPayload">Expected payload</param>
        /// <param name="allowedPayloadTagTypes">Payload tag types that are additionally allowed in PDU</param>
        /// <returns></returns>
        private static bool HasUnexpectedPayload(Pdu pdu, PduPayload expectedPayload, uint[] allowedPayloadTagTypes)
        {
            foreach (ITlvTag child in pdu.GetChildren())
            {
                if (child.Type == Constants.PduHeader.TagType || child.Type == Constants.Pdu.MacTagType)
                {
                    continue;
                }

                if (!ReferenceEquals(child, expectedPayload) && (allowedPayloadTagTypes == null || Array.IndexOf(allowedPayloadTagTypes, child.Type) < 0))
                {
                    return true;
                }
            }

            return false;
        }

        private static void CheckMacAlgorithm(ImprintTag mac, HashAlgorithm expectedMacAlgorithm)
        {
            if (mac != null && mac.Value.Algorithm.Id != expectedMacAlgorithm.Id)
            {
                throw new KsiServiceException(string.Format("HMAC algorithm mismatch. Expected {0}, received {1}", expectedMacAlgorithm.Name, mac.Value.Algorithm.Name));
            }
        }

        private static string FormatServerErrorStatus(ulong status, string errorMessage)
        {
            return "Server responded with error message. Status: " + status + "; Message: " + errorMessage + ".";
        }
    }
}