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

using System.Collections.Generic;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     TLV element containing other TLV elements.
    /// </summary>
    public interface ICompositeTag : ITlvTag, IEnumerable<ITlvTag>
    {
        /// <summary>
        ///     Get TLV child object
        /// </summary>
        /// <param name="i">tlv element position</param>
        /// <returns>TLV element at given position</returns>
        ITlvTag this[int i] { get; }

        /// <summary>
        ///     Get TLV element list size
        /// </summary>
        int Count { get; }

        /// <summary>
        ///     Get array of child elements.
        /// </summary>
        ITlvTag[] GetChildren();
    }
}