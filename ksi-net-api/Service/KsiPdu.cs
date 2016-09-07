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

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI PDU.
    /// </summary>
    public abstract class KsiPdu : CompositeTag
    {
        private ImprintTag _mac;

        /// <summary>
        ///     Get PDU payload.
        /// </summary>
        public abstract KsiPduPayload Payload { get; }

        /// <summary>
        ///     Get and set PDU header
        /// </summary>
        public KsiPduHeader Header { get; protected set; }

        /// <summary>
        ///     Create KSI PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected KsiPdu(ITlvTag tag) : base(tag)
        {
            int headerCount = 0;
            int headerIndex = 0;
            int payloadCount = 0;
            int macCount = 0;
            int macIndex = 0;
            bool hasErrorPayload = false;

            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.AggregationErrorPayload.TagType:
                        hasErrorPayload = true;
                        payloadCount++;
                        break;
                    case Constants.AggregationRequestPayload.TagType:
                    case Constants.AggregationResponsePayload.TagType:
                    case Constants.AggregationConfigRequestPayload.TagType:
                    case Constants.AggregationConfigResponsePayload.TagType:
                    case Constants.ExtendRequestPayload.TagType:
                    case Constants.ExtendResponsePayload.TagType:
                        payloadCount++;
                        break;
                    case Constants.ExtendErrorPayload.TagType:
                        hasErrorPayload = true;
                        payloadCount++;
                        break;
                    case Constants.KsiPduHeader.TagType:
                        this[i] = Header = new KsiPduHeader(childTag);
                        headerCount++;
                        headerIndex = i;
                        break;
                    case Constants.KsiPdu.MacTagType:
                        this[i] = _mac = new ImprintTag(childTag);
                        macCount++;
                        macIndex = i;
                        break;
                }
            }

            if (payloadCount != 1)
            {
                throw new TlvException("Exactly one payload must exist in KSI PDU.");
            }

            if (!hasErrorPayload)
            {
                if (headerCount != 1)
                {
                    throw new TlvException("Exactly one header must exist in KSI PDU.");
                }

                if (headerIndex != 0)
                {
                    throw new TlvException("Header must be the first element in KSI PDU.");
                }

                if (macCount != 1)
                {
                    throw new TlvException("Exactly one HMAC must exist in KSI PDU");
                }

                if (macIndex != Count - 1)
                {
                    throw new TlvException("HMAC must be the last element in KSI PDU");
                }
            }
        }

        /// <summary>
        ///     Create aggregation pdu TLV element from KSI header and payload.
        /// </summary>
        /// <param name="tagType">PDU TLV tag type</param>
        /// <param name="header">KSI PDU header</param>
        /// <param name="payload">aggregation payload</param>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <param name="key">hmac key</param>
        protected KsiPdu(uint tagType, KsiPduHeader header, KsiPduPayload payload, HashAlgorithm hmacAlgorithm, byte[] key)
            : base(tagType, false, false, new ITlvTag[] { header, payload, GetEmptyHashMacTag(hmacAlgorithm) })
        {
            if (header == null)
            {
                throw new TlvException("Invalid header TLV: null.");
            }

            if (payload == null)
            {
                throw new TlvException("Invalid payload TLV: null.");
            }

            if (hmacAlgorithm == null)
            {
                throw new TlvException("Invalid HMAC algorithm: null.");
            }

            Header = header;
            SetHmacValue(hmacAlgorithm, key);
        }

        /// <summary>
        ///     Create KSI PDU from PDU header and data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element list</param>
        protected KsiPdu(uint type, bool nonCritical, bool forward, ITlvTag[] value)
            : base(type, nonCritical, forward, value)
        {
        }

        /// <summary>
        /// Set HMAC tag value
        /// </summary>
        /// <param name="hmacAlgorithm"></param>
        /// <param name="key"></param>
        protected void SetHmacValue(HashAlgorithm hmacAlgorithm, byte[] key)
        {
            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.KsiPdu.MacTagType:
                        this[i] = _mac = CreateHashMacTag(GetHashMacValue(hmacAlgorithm, key));
                        break;
                }
            }
        }

        /// <summary>
        ///     Calculate HMAC value.
        /// </summary>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <param name="key">HMAC key</param>
        private DataHash GetHashMacValue(HashAlgorithm hmacAlgorithm, byte[] key)
        {
            MemoryStream stream = new MemoryStream();
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(this);
                byte[] target = new byte[stream.Length - hmacAlgorithm.Length];
                Array.Copy(stream.ToArray(), 0, target, 0, target.Length);

                IHmacHasher hasher = KsiProvider.CreateHmacHasher(hmacAlgorithm);
                return hasher.GetHash(key, target);
            }
        }

        /// <summary>
        /// Returns HMAC tag containing given data hash value
        /// </summary>
        /// <param name="dataHash">Data hash</param>
        /// <returns></returns>
        private static ImprintTag CreateHashMacTag(DataHash dataHash)
        {
            return new ImprintTag(Constants.KsiPdu.MacTagType, false, false, dataHash);
        }

        /// <summary>
        /// Get HMAC tag that has hash algorithm set, but hash value is a byte array containing zeros.
        /// </summary>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <returns></returns>
        protected static ImprintTag GetEmptyHashMacTag(HashAlgorithm hmacAlgorithm)
        {
            byte[] imprintBytes = new byte[hmacAlgorithm.Length + 1];
            imprintBytes[0] = hmacAlgorithm.Id;
            return CreateHashMacTag(new DataHash(imprintBytes));
        }

        /// <summary>
        ///     Validate mac attached to KSI PDU.
        /// </summary>
        /// <param name="key">message key</param>
        /// <returns>true if MAC is valid</returns>
        public bool ValidateMac(byte[] key)
        {
            if (_mac == null)
            {
                return false;
            }

            return GetHashMacValue(_mac.Value.Algorithm, key).Equals(_mac.Value);
        }
    }
}