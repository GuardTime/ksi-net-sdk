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

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation Error payload TLV element.
    /// </summary>
    public abstract class ErrorPayload : KsiPduPayload
    {
        /// <summary>
        ///     Create aggregation error payload TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <param name="expectedTagType">expected tag type</param>
        protected ErrorPayload(ITlvTag tag, uint expectedTagType) : base(tag)
        {
            if (Type != expectedTagType)
            {
                throw new TlvException("Invalid aggregation error type(" + Type + ").");
            }

            int statusCount = 0;
            int errorMessageCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.KsiPduPayload.StatusTagType:
                        IntegerTag statusTag = new IntegerTag(childTag);
                        Status = statusTag.Value;
                        statusCount++;
                        break;
                    case Constants.KsiPduPayload.ErrorMessageTagType:
                        StringTag errorMessageTag = new StringTag(childTag);
                        ErrorMessage = errorMessageTag.Value;
                        errorMessageCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (statusCount != 1)
            {
                throw new TlvException("Exactly one status code must exist in aggregation error.");
            }

            if (errorMessageCount > 1)
            {
                throw new TlvException("Only one error message is allowed in aggregation error.");
            }
        }

        /// <summary>
        ///     Get aggregation error status code.
        /// </summary>
        public ulong Status { get; }

        /// <summary>
        ///     Get aggregation error message if it exists.
        /// </summary>
        public string ErrorMessage { get; }
    }
}