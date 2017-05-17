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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Protocol Data Unit
    /// </summary>
    public abstract class Pdu : CompositeTag
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        int _headerIndex;
        int _macIndex;

        /// <summary>
        /// List on payloads
        /// </summary>
        public List<PduPayload> Payloads { get; } = new List<PduPayload>();

        /// <summary>
        /// Error payload
        /// </summary>
        public ErrorPayload ErrorPayload { get; set; }

        /// <summary>
        ///     Get and set PDU header
        /// </summary>
        public PduHeader Header { get; private set; }

        /// <summary>
        ///     Create PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected Pdu(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            foreach (uint tagType in Constants.AllPayloadTypes)
            {
                if (tagType == childTag.Type)
                {
                    return childTag;
                }
            }

            switch (childTag.Type)
            {
                case Constants.PduHeader.TagType:
                    _headerIndex = Count;
                    return Header = childTag as PduHeader ?? new PduHeader(childTag);
                case Constants.Pdu.MacTagType:
                    _macIndex = Count;
                    return Mac = GetImprintTag(childTag);
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
                    throw new TlvException("Payloads are missing in PDU.");
                }

                if (tagCounter[Constants.PduHeader.TagType] != 1)
                {
                    throw new TlvException("Exactly one header must exist in PDU.");
                }

                if (_headerIndex != 0)
                {
                    throw new TlvException("Header must be the first element in PDU.");
                }

                if (tagCounter[Constants.Pdu.MacTagType] != 1)
                {
                    throw new TlvException("Exactly one MAC must exist in PDU");
                }

                if (_macIndex != Count - 1)
                {
                    throw new TlvException("MAC must be the last element in PDU");
                }
            }
        }

        /// <summary>
        ///     Create aggregation pdu TLV element from KSI header and payload.
        /// </summary>
        /// <param name="tagType">PDU TLV tag type</param>
        /// <param name="header">PDU header</param>
        /// <param name="payload">aggregation payload</param>
        /// <param name="macAlgorithm">MAC algorithm</param>
        /// <param name="key">hmac key</param>
        protected Pdu(uint tagType, PduHeader header, PduPayload payload, HashAlgorithm macAlgorithm, byte[] key)
            : base(tagType, false, false, new ITlvTag[] { header, payload, GetEmptyMacTag(macAlgorithm) })
        {
            SetMacValue(macAlgorithm, key);
        }

        /// <summary>
        /// MAC
        /// </summary>
        public ImprintTag Mac { get; private set; }

        /// <summary>
        /// Set MAC tag value
        /// </summary>
        /// <param name="macAlgorithm"></param>
        /// <param name="key">HMAC key</param>
        protected void SetMacValue(HashAlgorithm macAlgorithm, byte[] key)
        {
            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                if (childTag.Type == Constants.Pdu.MacTagType)
                {
                    this[i] = Mac = CreateMacTag(CalcMacValue(macAlgorithm, key));
                    break;
                }
            }
        }

        /// <summary>
        ///     Calculate MAC value.
        /// </summary>
        /// <param name="macAlgorithm">MAC algorithm</param>
        /// <param name="key">HMAC key</param>
        private DataHash CalcMacValue(HashAlgorithm macAlgorithm, byte[] key)
        {
            MemoryStream stream = new MemoryStream();
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(this);

                return CalcMacValue(stream.ToArray(), macAlgorithm, key);
            }
        }

        /// <summary>
        ///     Calculate MAC value.
        /// </summary>
        /// <param name="pduBytes">PDU encoded as byte array</param>
        /// <param name="macAlgorithm">MAC algorithm</param>
        /// <param name="key">HMAC key</param>
        private static DataHash CalcMacValue(byte[] pduBytes, HashAlgorithm macAlgorithm, byte[] key)
        {
            byte[] target = pduBytes.Length < macAlgorithm.Length ? new byte[0] : new byte[pduBytes.Length - macAlgorithm.Length];
            Array.Copy(pduBytes, 0, target, 0, target.Length);

            IHmacHasher hasher = KsiProvider.CreateHmacHasher(macAlgorithm);
            return hasher.GetHash(key, target);
        }

        /// <summary>
        /// Returns MAC tag containing given data hash value
        /// </summary>
        /// <param name="dataHash">Data hash</param>
        /// <returns></returns>
        private static ImprintTag CreateMacTag(DataHash dataHash)
        {
            return new ImprintTag(Constants.Pdu.MacTagType, false, false, dataHash);
        }

        /// <summary>
        /// Get MAC tag that has hash algorithm set, but hash value is a byte array containing zeros.
        /// </summary>
        /// <param name="macAlgorithm">MAC algorithm</param>
        /// <returns></returns>
        protected static ImprintTag GetEmptyMacTag(HashAlgorithm macAlgorithm)
        {
            if (macAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(macAlgorithm));
            }

            byte[] imprintBytes = new byte[macAlgorithm.Length + 1];
            imprintBytes[0] = macAlgorithm.Id;
            return CreateMacTag(new DataHash(imprintBytes));
        }

        /// <summary>
        ///     Validate PDU against given MAC.
        /// </summary>
        /// <param name="pduBytes">PDU encoded as byte array</param>
        /// <param name="mac">MAC</param>
        /// <param name="key">message key</param>
        /// <returns>true if MAC is valid</returns>
        public static bool ValidateMac(byte[] pduBytes, ImprintTag mac, byte[] key)
        {
            if (pduBytes == null)
            {
                throw new ArgumentNullException(nameof(pduBytes));
            }

            if (mac == null)
            {
                throw new ArgumentNullException(nameof(mac));
            }

            if (pduBytes.Length < mac.Value.Algorithm.Length)
            {
                Logger.Warn("PDU MAC validation failed. PDU bytes array is too short to contain given MAC.");
                return false;
            }

            DataHash calculatedMac = CalcMacValue(pduBytes, mac.Value.Algorithm, key);

            if (!calculatedMac.Equals(mac.Value))
            {
                Logger.Warn("PDU MAC validation failed. Calculated MAC and given MAC do no match.");
                return false;
            }

            return true;
        }
    }
}