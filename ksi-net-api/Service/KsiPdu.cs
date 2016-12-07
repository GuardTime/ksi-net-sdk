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
using System.Collections.Generic;
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

        int _headerIndex;
        int _macIndex;

        /// <summary>
        /// List on payloads
        /// </summary>
        protected List<KsiPduPayload> Payloads { get; } = new List<KsiPduPayload>();

        /// <summary>
        /// Error payload
        /// </summary>
        protected KsiPduPayload ErrorPayload { get; set; }

        /// <summary>
        ///     Get and set PDU header
        /// </summary>
        public KsiPduHeader Header { get; private set; }

        /// <summary>
        ///     Create KSI PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected KsiPdu(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            if (Constants.PayloadTypes.Contains(childTag.Type))
            {
                return childTag;
            }

            if (childTag.Type == Constants.KsiPduHeader.TagType)
            {
                _headerIndex = Count;
                return Header = childTag as KsiPduHeader ?? new KsiPduHeader(childTag);
            }

            if (childTag.Type == Constants.KsiPdu.MacTagType)
            {
                _macIndex = Count;
                return _mac = GetImprintTag(childTag);
            }

            return base.ParseChild(childTag);
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate(TagCounter tagCounter)
        {
            base.Validate(tagCounter);

            if (ErrorPayload == null)
            {
                if (Payloads.Count == 0)
                {
                    throw new TlvException("Payloads are missing in KSI PDU.");
                }

                if (tagCounter[Constants.KsiPduHeader.TagType] != 1)
                {
                    throw new TlvException("Exactly one header must exist in KSI PDU.");
                }

                if (_headerIndex != 0)
                {
                    throw new TlvException("Header must be the first element in KSI PDU.");
                }

                if (tagCounter[Constants.KsiPdu.MacTagType] != 1)
                {
                    throw new TlvException("Exactly one HMAC must exist in KSI PDU");
                }

                if (_macIndex != Count - 1)
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
        /// Get payload of a given type
        /// </summary>
        /// <typeparam name="T">KSI PDU payload type</typeparam>
        /// <returns></returns>
        protected T GetPayload<T>() where T : KsiPduPayload
        {
            foreach (KsiPduPayload payload in Payloads)
            {
                T p = payload as T;
                if (p != null)
                {
                    return p;
                }
            }

            return null;
        }

        /// <summary>
        /// Get payloads of a given type
        /// </summary>
        /// <typeparam name="T">KSI PDU payload type</typeparam>
        /// <returns></returns>
        protected IEnumerable<T> GetPayloads<T>() where T : KsiPduPayload
        {
            foreach (KsiPduPayload payload in Payloads)
            {
                T p = payload as T;
                if (p != null)
                {
                    yield return p;
                }
            }
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
                        this[i] = _mac = CreateHashMacTag(CalcHashMacValue(hmacAlgorithm, key));
                        break;
                }
            }
        }

        /// <summary>
        ///     Calculate HMAC value.
        /// </summary>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <param name="key">HMAC key</param>
        private DataHash CalcHashMacValue(HashAlgorithm hmacAlgorithm, byte[] key)
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

            return CalcHashMacValue(_mac.Value.Algorithm, key).Equals(_mac.Value);
        }
    }
}