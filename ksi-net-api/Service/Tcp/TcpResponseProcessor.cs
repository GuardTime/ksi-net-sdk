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
using System.Collections.Generic;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Service.Tcp
{
    /// <summary>
    /// Class for processing TCP request response bytes.
    /// Corresponding async results are searched and marked as done when parsing data received via TCP.
    /// </summary>
    public class TcpResponseProcessor
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private byte[] _receivedBytes;
        private readonly TcpAsyncResultCollection _asyncResults;

        /// <summary>
        /// Create TCP request response processor instance
        /// </summary>
        /// <param name="asyncResults">Collection of async results associated with TCP requests. Corresponding async results are searched and marked as done when parsing data received via TCP.</param>
        public TcpResponseProcessor(TcpAsyncResultCollection asyncResults)
        {
            _asyncResults = asyncResults;
            Clear();
        }

        /// <summary>
        /// Clear received data
        /// </summary>
        public void Clear()
        {
            _receivedBytes = new byte[0];
        }

        /// <summary>
        /// Return received bytes that are not processed.
        /// </summary>
        /// <returns></returns>
        public string GetEncodedReceivedData()
        {
            return Base16.Encode(_receivedBytes);
        }

        /// <summary>
        /// Process received data. Corresponding async results are searched and marked as done.
        /// </summary>
        /// <param name="receivedDataBuffer">Received data buffer</param>
        /// <param name="receivedByteCount">Number of bytes received</param>
        public void ProcessReceivedData(byte[] receivedDataBuffer, int receivedByteCount)
        {
            Logger.Debug("{0} bytes received.", receivedByteCount);

            int oldLength = _receivedBytes.Length;
            Array.Resize(ref _receivedBytes, _receivedBytes.Length + receivedByteCount);
            Array.Copy(receivedDataBuffer, 0, _receivedBytes, oldLength, receivedByteCount);

            while (_receivedBytes.Length >= 4)
            {
                ushort firstTlvLength = Util.GetTlvLength(_receivedBytes);

                if (firstTlvLength > _receivedBytes.Length)
                {
                    break;
                }

                byte[] data = new byte[firstTlvLength];
                Array.Copy(_receivedBytes, 0, data, 0, firstTlvLength);

                if (!ProcessPdu(data))
                {
                    Logger.Warn("Could not get payload from response PDU: " + Base16.Encode(data));
                }

                // remove already handled data
                byte[] newResultData = new byte[_receivedBytes.Length - firstTlvLength];
                Array.Copy(_receivedBytes, firstTlvLength, newResultData, 0, newResultData.Length);
                _receivedBytes = newResultData;
            }
        }

        /// <summary>
        /// Finds all asyncResults matching response payloads in given PDU and marks them as completed.
        /// </summary>
        /// <param name="pduBytes">PDU bytes</param>
        /// <returns></returns>
        private bool ProcessPdu(byte[] pduBytes)
        {
            bool isPayloadFound = false;

            using (TlvReader reader = new TlvReader(new MemoryStream(pduBytes)))
            {
                // iterate over all payloads in PDU
                foreach (KsiServiceResponsePayloadInfo payloadInfo in GetResponsePayloadInfos(reader.ReadTag()))
                {
                    isPayloadFound = true;
                    bool asyncResultFound = false;

                    foreach (TcpKsiServiceAsyncResult asyncResult in GetAsyncResults(payloadInfo))
                    {
                        asyncResultFound = true;

                        if (!asyncResult.IsCompleted)
                        {
                            asyncResult.ResultStream = new MemoryStream(pduBytes);
                            Logger.Debug("Response payload received. Request type: {0}; Response payload type: {1}; (request id: {2}).", asyncResult.ServiceRequestType,
                                payloadInfo.ResponsePayloadType, asyncResult.RequestId);
                            asyncResult.SetComplete();
                        }
                        else
                        {
                            Logger.Debug("AsyncResult already marked as Completed. Request type: {0}; Response payload type: {1}; (request id: {2}).",
                                asyncResult.ServiceRequestType, payloadInfo.ResponsePayloadType, asyncResult.RequestId);
                        }

                        _asyncResults.Remove(asyncResult);
                    }

                    if (!asyncResultFound)
                    {
                        Logger.Warn("No request data found corresponding to the respose payload. Response info: {0}; Response TLV: {1}", payloadInfo, Base16.Encode(pduBytes));
                    }
                }
            }

            return isPayloadFound;
        }

        /// <summary>
        /// Returns asyncResults according to response payload.
        /// If aggregation response payload then return asyncResult by request id.
        /// If error payload then return all asyncResults.
        /// If config response payload the return all asyncResults created by config requests.
        /// </summary>
        /// <param name="payloadInfo">Response payload info</param>
        /// <returns></returns>
        private List<TcpKsiServiceAsyncResult> GetAsyncResults(KsiServiceResponsePayloadInfo payloadInfo)
        {
            List<TcpKsiServiceAsyncResult> list = new List<TcpKsiServiceAsyncResult>();
            ulong[] keys = _asyncResults.GetKeys();

            switch (payloadInfo.ResponsePayloadType)
            {
                case KsiServiceResponsePayloadType.Aggregation:
                case KsiServiceResponsePayloadType.Extending:
                    foreach (ulong key in keys)
                    {
                        if (key == payloadInfo.RequestId)
                        {
                            TcpKsiServiceAsyncResult asyncResult = _asyncResults.GetValue(key);

                            if (asyncResult == null)
                            {
                                continue;
                            }

                            list.Add(asyncResult);
                        }
                    }
                    break;

                case KsiServiceResponsePayloadType.AggregatorConfig:
                    // return all async results of all aggregator configuration requests 
                    foreach (ulong key in keys)
                    {
                        TcpKsiServiceAsyncResult asyncResult = _asyncResults.GetValue(key);

                        if (asyncResult?.ServiceRequestType == KsiServiceRequestType.AggregatorConfig)
                        {
                            list.Add(asyncResult);
                        }
                    }
                    break;

                case KsiServiceResponsePayloadType.ExtenderConfig:
                    // return all async results of all extender configuration requests 
                    foreach (ulong key in keys)
                    {
                        TcpKsiServiceAsyncResult asyncResult = _asyncResults.GetValue(key);

                        if (asyncResult?.ServiceRequestType == KsiServiceRequestType.ExtenderConfig)
                        {
                            list.Add(asyncResult);
                        }
                    }
                    break;
                case KsiServiceResponsePayloadType.Error:
                    foreach (ulong key in keys)
                    {
                        TcpKsiServiceAsyncResult asyncResult = _asyncResults.GetValue(key);

                        if (asyncResult != null)
                        {
                            list.Add(asyncResult);
                        }
                    }
                    break;
                default:
                    throw new KsiServiceProtocolException("Unhandled payload type.");
            }

            return list;
        }

        /// <summary>
        /// Get info of all payloads that response PDU contains.
        /// </summary>
        /// <param name="pdu"></param>
        /// <returns></returns>
        private List<KsiServiceResponsePayloadInfo> GetResponsePayloadInfos(RawTag pdu)
        {
            switch (pdu.Type)
            {
                case Constants.AggregationResponsePdu.TagType:
                    return GetAggregatorResponsePayloadInfos(pdu);
                case Constants.LegacyAggregationPdu.TagType:
                    return new List<KsiServiceResponsePayloadInfo>() { GetLegacyAggregatorResponsePayloadInfos(pdu) };
                case Constants.ExtendResponsePdu.TagType:
                    return GetExtenderResponsePayloadInfos(pdu);
                case Constants.LegacyExtendPdu.TagType:
                    return new List<KsiServiceResponsePayloadInfo>() { GetLegacyExtenderResponsePayloadInfos(pdu) };
                default:
                    throw new KsiServiceProtocolException("Unknown response PDU type: " + pdu.Type);
            }
        }

        private static List<KsiServiceResponsePayloadInfo> GetAggregatorResponsePayloadInfos(RawTag pdu)
        {
            List<KsiServiceResponsePayloadInfo> list = new List<KsiServiceResponsePayloadInfo>();
            IEnumerable<RawTag> children = GetChildren(pdu.Value);

            bool containsUnknownPayload = false;
            foreach (RawTag child in children)
            {
                switch (child.Type)
                {
                    case Constants.AggregationResponsePayload.TagType:
                        RawTag requestIdTag = GetTagByType(child.Value, Constants.PduPayload.RequestIdTagType);
                        if (requestIdTag == null)
                        {
                            throw new KsiServiceProtocolException("Cannot find request id tag from aggregation response payload.");
                        }
                        list.Add(new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.Aggregation, new IntegerTag(requestIdTag).Value));
                        break;

                    case Constants.AggregatorConfigResponsePayload.TagType:
                        list.Add(new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.AggregatorConfig));
                        break;
                    case Constants.ErrorPayload.TagType:
                        list.Add(new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.Error));
                        break;
                    case Constants.PduHeader.TagType:
                    case Constants.Pdu.MacTagType:
                        break;
                    default:
                        containsUnknownPayload = true;
                        break;
                }
            }

            if (containsUnknownPayload)
            {
                // try to parse PDU to check if critical unknown tags are included in which case a parsing exceptions is thrown by AggregationResponsePdu
                AggregationResponsePdu aggregationResponsePdu = new AggregationResponsePdu(pdu);
                Logger.Warn(string.Format("TCP response processor received unexpected response payloads!{0}PDU:{0}{1}", Environment.NewLine, aggregationResponsePdu));
            }

            return list;
        }

        private static List<KsiServiceResponsePayloadInfo> GetExtenderResponsePayloadInfos(RawTag pdu)
        {
            List<KsiServiceResponsePayloadInfo> list = new List<KsiServiceResponsePayloadInfo>();
            IEnumerable<RawTag> children = GetChildren(pdu.Value);

            bool containsUnknownPayload = false;
            foreach (RawTag child in children)
            {
                switch (child.Type)
                {
                    case Constants.ExtendResponsePayload.TagType:
                        RawTag requestIdTag = GetTagByType(child.Value, Constants.PduPayload.RequestIdTagType);
                        if (requestIdTag == null)
                        {
                            throw new KsiServiceProtocolException("Cannot find request id tag from extender response payload.");
                        }
                        list.Add(new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.Extending, new IntegerTag(requestIdTag).Value));
                        break;

                    case Constants.ExtenderConfigResponsePayload.TagType:
                        list.Add(new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.ExtenderConfig));
                        break;
                    case Constants.ErrorPayload.TagType:
                        list.Add(new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.Error));
                        break;
                    case Constants.PduHeader.TagType:
                    case Constants.Pdu.MacTagType:
                        break;
                    default:
                        containsUnknownPayload = true;
                        break;
                }
            }

            if (containsUnknownPayload)
            {
                // try to parse PDU to check if critical unknown tags are included in which case a parsing exceptions is thrown by ExtendResponsePdu
                ExtendResponsePdu extendResponsePdu = new ExtendResponsePdu(pdu);
                Logger.Warn(string.Format("TCP response processor received unexpected response payloads!{0}PDU:{0}{1}", Environment.NewLine, extendResponsePdu));
            }

            return list;
        }

        private static KsiServiceResponsePayloadInfo GetLegacyAggregatorResponsePayloadInfos(RawTag pdu)
        {
            RawTag payload = GetTagByType(pdu.Value, Constants.AggregationResponsePayload.LegacyTagType, Constants.LegacyAggregationErrorPayload.TagType);

            switch (payload.Type)
            {
                case Constants.AggregationResponsePayload.LegacyTagType:
                    RawTag requestIdTag = GetTagByType(payload.Value, Constants.PduPayload.RequestIdTagType);
                    if (requestIdTag == null)
                    {
                        throw new KsiServiceProtocolException("Cannot find request id tag from legacy aggregation response payload.");
                    }
                    return new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.Aggregation, new IntegerTag(requestIdTag).Value);
                case Constants.LegacyAggregationErrorPayload.TagType:
                    return new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.Error);
                default:
                    throw new KsiServiceProtocolException("Cannot find a known payload from legacy PDU.");
            }
        }

        private static KsiServiceResponsePayloadInfo GetLegacyExtenderResponsePayloadInfos(RawTag pdu)
        {
            RawTag payload = GetTagByType(pdu.Value, Constants.ExtendResponsePayload.LegacyTagType, Constants.LegacyExtendErrorPayload.TagType);

            switch (payload.Type)
            {
                case Constants.ExtendResponsePayload.LegacyTagType:
                    RawTag requestIdTag = GetTagByType(payload.Value, Constants.PduPayload.RequestIdTagType);
                    if (requestIdTag == null)
                    {
                        throw new KsiServiceProtocolException("Cannot find request id tag from legacy extender response payload.");
                    }
                    return new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.Extending, new IntegerTag(requestIdTag).Value);
                case Constants.LegacyExtendErrorPayload.TagType:
                    return new KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType.Error);
                default:
                    throw new KsiServiceProtocolException("Cannot find a known payload from legacy PDU.");
            }
        }

        /// <summary>
        /// Get all child tags from byte array
        /// </summary>
        /// <param name="bytes">byte array containing tags</param>
        /// <returns></returns>
        private static IEnumerable<RawTag> GetChildren(byte[] bytes)
        {
            using (TlvReader tlvReader = new TlvReader(new MemoryStream(bytes)))
            {
                while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                {
                    RawTag raw = tlvReader.ReadTag();
                    yield return raw;
                }
            }
        }

        /// <summary>
        /// Get the first tag from byte array by tag type ID
        /// </summary>
        /// <param name="bytes">byte array containing tags</param>
        /// <param name="typeId">tag type ID</param>
        /// <returns></returns>
        private static RawTag GetTagByType(byte[] bytes, params uint[] typeId)
        {
            foreach (RawTag tag in GetChildren(bytes))
            {
                if (Array.Exists(typeId, t => t == tag.Type))
                {
                    return tag;
                }
            }

            return null;
        }
    }
}