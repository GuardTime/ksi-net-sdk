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

using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// PDU payload.
    /// </summary>
    public abstract class PduPayload : CompositeTag
    {
        /// <summary>
        ///     Create PDU payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected PduPayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        ///     Create PDU payload from data.
        /// </summary>
        /// <param name="type">TLV type</param>
        /// <param name="nonCritical">is TLV non critical</param>
        /// <param name="forward">is TLV forwarded</param>
        /// <param name="childTags">List of child TLV elements</param>
        protected PduPayload(uint type, bool nonCritical, bool forward, ITlvTag[] childTags)
            : base(type, nonCritical, forward, childTags)
        {
        }
    }
}