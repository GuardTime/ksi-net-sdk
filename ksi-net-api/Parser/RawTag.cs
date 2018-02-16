/*
 * Copyright 2013-2018 Guardtime, Inc.
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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     Octet String TLV element.
    /// </summary>
    public class RawTag : TlvTag
    {
        private readonly byte[] _value;

        /// <summary>
        ///     Create new octet string TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public RawTag(ITlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                throw new TlvException("Invalid TLV element encoded value: null.");
            }

            _value = data;
        }

        /// <summary>
        ///     Create new octet string TLV element from data
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element byte array value</param>
        public RawTag(uint type, bool nonCritical, bool forward, byte[] value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            _value = Util.Clone(value);
        }

        /// <summary>
        ///     Create new octet string TLV element from data
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element byte array value</param>
        /// <param name="isReadAsTlv16">Indicates that TLV element was created using tlv16 encoding</param>
        public RawTag(uint type, bool nonCritical, bool forward, byte[] value, bool? isReadAsTlv16 = null)
            : this(type, nonCritical, forward, value)
        {
            IsReadAsTlv16 = isReadAsTlv16;
        }

        /// <summary>
        ///     Get TLV element byte array value.
        /// </summary>
        public byte[] Value => Util.Clone(_value);

        /// <summary>
        ///     Return TLV element byte array value.
        /// </summary>
        /// <returns>TLV element value</returns>
        public override byte[] EncodeValue()
        {
            return Value;
        }

        /// <summary>
        ///     Get TLV element hash code.
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                int res = 1;
                foreach (byte value in _value)
                {
                    res = 31 * res + value;
                }

                return res + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        /// <summary>
        /// Indicates that TLV element was created using tlv16 encoding
        /// </summary>
        public bool? IsReadAsTlv16 { get; }
    }
}