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
    ///     KSI PDU.
    /// </summary>
    [Obsolete]
    public abstract class LegacyKsiPdu : CompositeTag
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private readonly KsiPduHeader _header;

        /// <summary>
        ///     Get PDU payload.
        /// </summary>
        public abstract KsiPduPayload Payload { get; }

        /// <summary>
        ///     Create KSI PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        [Obsolete]
        protected LegacyKsiPdu(ITlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.KsiPduHeader.TagType:
                        this[i] = _header = new KsiPduHeader(childTag);
                        break;
                    case Constants.KsiPdu.MacTagType:
                        this[i] = Mac = new ImprintTag(childTag);
                        break;
                }
            }
        }

        /// <summary>
        ///     Create KSI PDU from PDU header and data.
        /// </summary>
        /// <param name="header">KSI PDU header</param>
        /// <param name="mac">KSI pdu hmac</param>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element list</param>
        [Obsolete]
        protected LegacyKsiPdu(KsiPduHeader header, ImprintTag mac, uint type, bool nonCritical, bool forward, ITlvTag[] value)
            : base(type, nonCritical, forward, value)
        {
            if (header == null)
            {
                throw new TlvException("Invalid TLV header: null.");
            }

            if (mac == null)
            {
                throw new TlvException("Invalid hashmac hash: null");
            }

            _header = header;
            Mac = mac;
        }

        /// <summary>
        /// MAC
        /// </summary>
        public ImprintTag Mac { get; }

        /// <summary>
        ///     Calculate MAC and attach it to PDU.
        /// </summary>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <param name="key">hmac key</param>
        /// <param name="header">KSI header</param>
        /// <param name="payload">KSI payload</param>
        public static ImprintTag GetHashMacTag(HashAlgorithm hmacAlgorithm, byte[] key, KsiPduHeader header, KsiPduPayload payload)
        {
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(header);
                writer.WriteTag(payload);
                return new ImprintTag(Constants.KsiPdu.MacTagType, false, false, CalculateMac(hmacAlgorithm, key, ((MemoryStream)writer.BaseStream).ToArray()));
            }
        }

        /// <summary>
        ///     Calculate HMAC for data with given key.
        /// </summary>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <param name="key">hmac key</param>
        /// <param name="data">hmac calculation data</param>
        /// <returns>hmac data hash</returns>
        private static DataHash CalculateMac(HashAlgorithm hmacAlgorithm, byte[] key, byte[] data)
        {
            IHmacHasher hmac = KsiProvider.CreateHmacHasher(hmacAlgorithm);
            return hmac.GetHash(key, data);
        }

        /// <summary>
        ///     Validate mac attached to KSI PDU.
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