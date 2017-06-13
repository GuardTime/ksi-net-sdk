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

namespace Guardtime.KSI.Service
{
    public partial class TcpKsiServiceProtocol
    {
        /// <summary>
        /// Class for processing received bytes.
        /// </summary>
        private class TcpResponseProcessor
        {
            private byte[] _receivedBytes;
            private readonly AsyncResultCollection _asyncResults;

            public TcpResponseProcessor(AsyncResultCollection asyncResults)
            {
                _asyncResults = asyncResults;
                Clear();
            }

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
            /// Process received data.
            /// </summary>
            /// <param name="receiveDataBuffer">Received data buffer</param>
            /// <param name="receivedByteCount">Number of bytes received</param>
            public void ProcessReceivedData(byte[] receiveDataBuffer, int receivedByteCount)
            {
                Logger.Debug("{0} bytes received.", receivedByteCount);

                int oldLength = _receivedBytes.Length;
                Array.Resize(ref _receivedBytes, _receivedBytes.Length + receivedByteCount);
                Array.Copy(receiveDataBuffer, 0, _receivedBytes, oldLength, receivedByteCount);

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
                        Logger.Warn("Unknown response TLV: " + Base16.Encode(data));
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
                    foreach (ResponsePayloadInfo payloadInfo in GetResponsePayloadInfos(reader.ReadTag()))
                    {
                        isPayloadFound = true;
                        bool asyncResultFound = false;

                        foreach (TcpKsiServiceProtocolAsyncResult asyncResult in GetAsyncResults(payloadInfo))
                        {
                            asyncResultFound = true;

                            if (!asyncResult.IsCompleted)
                            {
                                asyncResult.ResultStream = new MemoryStream(pduBytes);
                                Logger.Debug("Response payload received. Request type: {0}; Response payload type: {1}; (request id: {2}).", asyncResult.RequestType,
                                    payloadInfo.ResponsePayloadType, asyncResult.RequestId);
                                asyncResult.SetComplete(false);
                            }
                            else
                            {
                                Logger.Debug("AsyncResult already marked as Completed. Request type: {0}; Response payload type: {1}; (request id: {2}).",
                                    asyncResult.RequestType, payloadInfo.ResponsePayloadType, asyncResult.RequestId);
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
            private IEnumerable<TcpKsiServiceProtocolAsyncResult> GetAsyncResults(ResponsePayloadInfo payloadInfo)
            {
                ulong[] keys = _asyncResults.GetKeys();

                switch (payloadInfo.ResponsePayloadType)
                {
                    case ResponsePayloadInfo.PayloadType.Aggregation:
                        foreach (ulong key in keys)
                        {
                            if (key == payloadInfo.RequestId)
                            {
                                TcpKsiServiceProtocolAsyncResult asyncResult = _asyncResults.GetValue(key);

                                if (asyncResult == null)
                                {
                                    continue;
                                }

                                yield return asyncResult;
                            }
                        }
                        break;
                    case ResponsePayloadInfo.PayloadType.Error:
                        foreach (ulong key in keys)
                        {
                            TcpKsiServiceProtocolAsyncResult asyncResult = _asyncResults.GetValue(key);

                            if (asyncResult != null)
                            {
                                yield return asyncResult;
                            }
                        }
                        break;
                    case ResponsePayloadInfo.PayloadType.Config:
                        foreach (ulong key in keys)
                        {
                            TcpKsiServiceProtocolAsyncResult asyncResult = _asyncResults.GetValue(key);

                            if (asyncResult?.RequestType == RequestType.AggregatorConfig)
                            {
                                yield return asyncResult;
                            }
                        }
                        break;
                    default:
                        throw new KsiServiceProtocolException("Unhandled payload type.");
                }
            }

            /// <summary>
            /// Get info of all payloads that response PDU contains.
            /// </summary>
            /// <param name="pdu"></param>
            /// <returns></returns>
            private IEnumerable<ResponsePayloadInfo> GetResponsePayloadInfos(RawTag pdu)
            {
                if (pdu.Type == Constants.AggregationResponsePdu.TagType)
                {
                    IEnumerable<RawTag> payloads = GetTagsByType(pdu.Value, Constants.AggregationResponsePayload.TagType, Constants.AggregatorConfigResponsePayload.TagType,
                        Constants.ErrorPayload.TagType);

                    foreach (RawTag payload in payloads)
                    {
                        switch (payload.Type)
                        {
                            case Constants.AggregationResponsePayload.TagType:
                                RawTag requestIdTag = GetTagByType(payload.Value, Constants.PduPayload.RequestIdTagType);
                                if (requestIdTag == null)
                                {
                                    throw new KsiServiceProtocolException("Cannot find request id tag from aggregation response payload.");
                                }
                                yield return new ResponsePayloadInfo(ResponsePayloadInfo.PayloadType.Aggregation, new IntegerTag(requestIdTag).Value);
                                break;
                            case Constants.AggregatorConfigResponsePayload.TagType:
                                yield return new ResponsePayloadInfo(ResponsePayloadInfo.PayloadType.Config);
                                break;
                            case Constants.ErrorPayload.TagType:
                                yield return new ResponsePayloadInfo(ResponsePayloadInfo.PayloadType.Error);
                                break;
                            default:
                                throw new KsiServiceProtocolException("Cannot find a known payload from PDU.");
                        }
                    }
                }

                else if (pdu.Type == Constants.LegacyAggregationPdu.TagType)
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
                            yield return new ResponsePayloadInfo(ResponsePayloadInfo.PayloadType.Aggregation, new IntegerTag(requestIdTag).Value);
                            break;
                        case Constants.LegacyAggregationErrorPayload.TagType:
                            yield return new ResponsePayloadInfo(ResponsePayloadInfo.PayloadType.Error);
                            break;
                        default:
                            throw new KsiServiceProtocolException("Cannot find a known payload from legacy PDU.");
                    }
                }
                else
                {
                    throw new KsiServiceProtocolException("Unknown response PDU type: " + pdu.Type);
                }
            }

            /// <summary>
            /// Get all tags from byte array by tag type IDs
            /// </summary>
            /// <param name="bytes">byte array containing tags</param>
            /// <param name="typeId">tag type ID</param>
            /// <returns></returns>
            private IEnumerable<RawTag> GetTagsByType(byte[] bytes, params uint[] typeId)
            {
                using (TlvReader tlvReader = new TlvReader(new MemoryStream(bytes)))
                {
                    while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                    {
                        RawTag raw = tlvReader.ReadTag();
                        if (Array.Exists(typeId, t => t == raw.Type))
                        {
                            yield return raw;
                        }
                    }
                }
            }

            /// <summary>
            /// Get the first tag from byte array by tag type ID
            /// </summary>
            /// <param name="bytes">byte array containing tags</param>
            /// <param name="typeId">tag type ID</param>
            /// <returns></returns>
            private RawTag GetTagByType(byte[] bytes, params uint[] typeId)
            {
                IEnumerator<RawTag> enumerator = GetTagsByType(bytes, typeId).GetEnumerator();
                return enumerator.MoveNext() ? enumerator.Current : null;
            }
        }

        /// <summary>
        /// Class containing response payload info (payload type and request ID)
        /// </summary>
        private class ResponsePayloadInfo
        {
            public enum PayloadType
            {
                Aggregation,
                Config,
                Error
            };

            public ResponsePayloadInfo(PayloadType responsePayloadType, ulong? requestId = null)
            {
                ResponsePayloadType = responsePayloadType;
                RequestId = requestId;
            }

            public PayloadType ResponsePayloadType { get; }

            public ulong? RequestId { get; }

            public override string ToString()
            {
                return string.Format("[Type: {0}; RequestId: {1}]", ResponsePayloadType, RequestId);
            }
        }
    }
}