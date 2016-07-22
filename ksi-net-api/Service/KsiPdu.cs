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

        protected KsiPduHeader Header { get; set; }

        /// <summary>
        ///     Create KSI PDU from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected KsiPdu(ITlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.KsiPduHeader.TagType:
                        this[i] = Header = new KsiPduHeader(childTag);
                        break;
                    case Constants.KsiPdu.MacTagType:
                        this[i] = _mac = new ImprintTag(childTag);
                        break;
                }
            }
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

        protected void SetHmacValue(HashAlgorithm hmacAlgorithm, byte[] key)
        {
            for (int i = 0; i < Count; i++)
            {
                ITlvTag childTag = this[i];

                switch (childTag.Type)
                {
                    case Constants.KsiPdu.MacTagType:
                        this[i] = _mac = CreateHashMacTag(GetHashMac(hmacAlgorithm, key));
                        break;
                }
            }
        }

        /// <summary>
        ///     Calculate MAC and attach it to PDU.
        /// </summary>
        /// <param name="hmacAlgorithm">HMAC algorithm</param>
        /// <param name="key">hmac key</param>
        protected DataHash GetHashMac(HashAlgorithm hmacAlgorithm, byte[] key)
        {
            // replace last n bytes with HMAC
            MemoryStream stream = new MemoryStream();
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(this);
                byte[] target = new byte[stream.Length - hmacAlgorithm.Length];
                Array.Copy(stream.ToArray(), 0, target, 0, target.Length);
                return CalculateMac(hmacAlgorithm, key, target);
            }
        }

        protected static ImprintTag GetEmptyHashMacTag(HashAlgorithm hmacAlgorithm)
        {
            byte[] imprintBytes = new byte[hmacAlgorithm.Length + 1];
            imprintBytes[0] = hmacAlgorithm.Id;
            return CreateHashMacTag(new DataHash(imprintBytes));
        }

        protected static ImprintTag CreateHashMacTag(DataHash dataHash)
        {
            return new ImprintTag(Constants.KsiPdu.MacTagType, false, false, dataHash);
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

            return GetHashMac(_mac.Value.Algorithm, key).Equals(_mac.Value);

            //using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            //{
            //    writer.WriteTag(Header);
            //    writer.WriteTag(Payload);

            //    DataHash hash = CalculateMac(_mac.Value.Algorithm, key, ((MemoryStream)writer.BaseStream).ToArray());
            //    return hash.Equals(_mac.Value);
            //}
        }
    }
}