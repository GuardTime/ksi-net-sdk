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
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Legacy Protocol Data Unit.
    /// </summary>
    [Obsolete]
    public abstract class LegacyPdu : CompositeTag
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private PduHeader _header;
        private PduPayload _payload;
        private int _payloadCount;
        private ErrorPayload _errorPayload;

        /// <summary>
        ///     Get PDU payload.
        /// </summary>
        public PduPayload Payload
        {
            get { return _payload; }
            protected set
            {
                _payload = value;
                _payloadCount++;
            }
        }

        /// <summary>
        /// Error payload
        /// </summary>
        public ErrorPayload ErrorPayload
        {
            get { return _errorPayload; }
            protected set
            {
                _errorPayload = value;
                _payloadCount++;
            }
        }

        /// <summary>
        ///     Create PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        [Obsolete]
        protected LegacyPdu(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.PduHeader.TagType:
                    return _header = childTag as PduHeader ?? new PduHeader(childTag);
                case Constants.Pdu.MacTagType:
                    return Mac = GetImprintTag(childTag);
                default:
                    return base.ParseChild(childTag);
            }
        }

        /// <summary>
        /// Validate the tag
        /// </summary>
        protected override void Validate(TagCounter tagCounter)
        {
            base.Validate(tagCounter);

            if (_payloadCount != 1)
            {
                throw new TlvException("Exactly one payload must exist in PDU.");
            }

            if (ErrorPayload == null)
            {
                if (tagCounter[Constants.PduHeader.TagType] != 1)

                {
                    throw new TlvException("Exactly one header must exist in PDU.");
                }

                if (tagCounter[Constants.Pdu.MacTagType] != 1)
                {
                    throw new TlvException("Exactly one mac must exist in PDU");
                }
            }
        }

        /// <summary>
        ///     Create PDU from PDU header and data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="childTags">List of child TLV elements</param>
        [Obsolete]
        protected LegacyPdu(uint type, bool nonCritical, bool forward, ITlvTag[] childTags)
            : base(type, nonCritical, forward, childTags)
        {
        }

        /// <summary>
        /// MAC
        /// </summary>
        public ImprintTag Mac { get; private set; }

        /// <summary>
        ///     Calculate MAC and attach it to PDU.
        /// </summary>
        /// <param name="macAlgorithm">MAC algorithm</param>
        /// <param name="key">hmac key</param>
        /// <param name="header">KSI header</param>
        /// <param name="payload">KSI payload</param>
        public static ImprintTag GetMacTag(HashAlgorithm macAlgorithm, byte[] key, PduHeader header, PduPayload payload)
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(header);
                writer.WriteTag(payload);
                return new ImprintTag(Constants.Pdu.MacTagType, false, false, CalculateMac(macAlgorithm, key, ((MemoryStream)writer.BaseStream).ToArray()));
            }
        }

        /// <summary>
        ///     Calculate MAC for data with given key.
        /// </summary>
        /// <param name="macAlgorithm">MAC algorithm</param>
        /// <param name="key">hmac key</param>
        /// <param name="data">data to calculate MAC from</param>
        /// <returns>mac data hash</returns>
        private static DataHash CalculateMac(HashAlgorithm macAlgorithm, byte[] key, byte[] data)
        {
            IHmacHasher hasher = KsiProvider.CreateHmacHasher(macAlgorithm);
            return hasher.GetHash(key, data);
        }

        /// <summary>
        ///     Validate mac attached to PDU.
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

            if (pduBytes.Length < 1)
            {
                Logger.Warn("PDU MAC validation failed. PDU bytes array is empty.");
                return false;
            }

            // We will use only header and payload for mac calculation.
            // It is assumed that mac tag is the last one.

            HashAlgorithm hashAlgorithm = mac.Value.Algorithm;
            int macTagLength = 3 + hashAlgorithm.Length; // tlv-8 header bytes + algorithm type byte + algorithm value

            bool tlv16 = (pduBytes[0] & Constants.Tlv.Tlv16Flag) != 0;

            int startFrom = tlv16 ? 4 : 2;
            int calcDataLength = pduBytes.Length - startFrom - macTagLength;

            if (calcDataLength < 0)
            {
                Logger.Warn("PDU MAC validation failed. PDU bytes array is too short to contain given MAC.");
                return false;
            }

            byte[] target = new byte[calcDataLength];
            Array.Copy(pduBytes, startFrom, target, 0, target.Length);

            DataHash calculatedMac = CalculateMac(hashAlgorithm, key, target);

            if (!calculatedMac.Equals(mac.Value))
            {
                Logger.Warn("PDU MAC validation failed. Calculated MAC and given MAC do no match.");
                return false;
            }

            return true;
        }
    }
}