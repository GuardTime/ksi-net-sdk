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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publication record TLV element to be used in signature.
    /// </summary>
    public sealed class PublicationRecordInSignature : PublicationRecord
    {
        /// <summary>
        ///     Create new publication record TLV element to be used in signature.
        /// </summary>
        /// <param name="tag">TLV element the publication record will be created from</param>
        public PublicationRecordInSignature(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.PublicationRecord.TagTypeInSignature)
            {
                throw new TlvException("Invalid publication record type(" + Type + ").");
            }
        }

        /// <summary>
        /// Create new publication record TLV element to be used in signature.
        /// </summary>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">child TLV element list</param>
        public PublicationRecordInSignature(bool nonCritical, bool forward, ITlvTag[] value) : base(Constants.PublicationRecord.TagTypeInSignature, nonCritical, forward, value)
        {
        }
    }
}