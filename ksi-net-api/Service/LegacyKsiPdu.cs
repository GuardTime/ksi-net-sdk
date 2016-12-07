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
    [Obsolete]
    public abstract class LegacyKsiPdu : CompositeTag
    {
        private KsiPduHeader _header;
        private ImprintTag _mac;
        private KsiPduPayload _payload;
        private int _payloadCount;
        private ErrorPayload _errorPayload;

        /// <summary>
        ///     Get PDU payload.
        /// </summary>
        public KsiPduPayload Payload
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
        ///     Create KSI PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        [Obsolete]
        protected LegacyKsiPdu(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.KsiPduHeader.TagType:
                    return _header = childTag as KsiPduHeader ?? new KsiPduHeader(childTag);
                case Constants.KsiPdu.MacTagType:
                    return _mac = GetImprintTag(childTag);
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
                throw new TlvException("Exactly one payload must exist in KSI PDU.");
            }

            if (ErrorPayload == null)
            {
                if (tagCounter[Constants.KsiPduHeader.TagType] != 1)

                {
                    throw new TlvException("Exactly one header must exist in KSI PDU.");
                }

                if (tagCounter[Constants.KsiPdu.MacTagType] != 1)
                {
                    throw new TlvException("Exactly one mac must exist in KSI PDU");
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
            _mac = mac;
        }

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
        /// <param name="key">message key</param>
        /// <returns>true if MAC is valid</returns>
        public bool ValidateMac(byte[] key)
        {
            if (_mac == null)
            {
                return false;
            }

            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(_header);
                writer.WriteTag(Payload);

                DataHash hash = CalculateMac(_mac.Value.Algorithm, key, ((MemoryStream)writer.BaseStream).ToArray());
                return hash.Equals(_mac.Value);
            }
        }
    }
}