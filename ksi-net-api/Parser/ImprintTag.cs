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
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     Imprint TLV element
    /// </summary>
    public class ImprintTag : TlvTag
    {
        /// <summary>
        ///     Create new imprint TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ImprintTag(ITlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                throw new TlvException("Invalid TLV element encoded value: null.");
            }
            Value = new DataHash(data);
        }

        /// <summary>
        ///     Create new imprint TLV element from data.
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">data hash</param>
        public ImprintTag(uint type, bool nonCritical, bool forward, DataHash value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            Value = value;
        }

        /// <summary>
        ///     Get TLV element data hash
        /// </summary>
        public DataHash Value { get; }

        /// <summary>
        ///     Encode data hash to byte array.
        /// </summary>
        /// <returns>Data hash as byte array</returns>
        public override byte[] EncodeValue()
        {
            return Value.Imprint;
        }

        /// <summary>
        ///     Get TLV element hash code.
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                return Value.GetHashCode() + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }
    }
}