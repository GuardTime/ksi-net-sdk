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

using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Sign request response payload.
    /// </summary>
    public abstract class SignRequestResponsePayload : RequestResponsePayload
    {
        /// <summary>
        ///     Create sign request response payload TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected SignRequestResponsePayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Get child tags that will be used to create a KSI signature
        /// </summary>
        /// <returns></returns>
        public ITlvTag[] GetSignatureChildTags()
        {
            List<ITlvTag> childTags = new List<ITlvTag>();

            foreach (ITlvTag childTag in this)
            {
                if (childTag.Type > 0x800 && childTag.Type < 0x900)
                {
                    childTags.Add(childTag);
                }
            }
            return childTags.ToArray();
        }
    }
}