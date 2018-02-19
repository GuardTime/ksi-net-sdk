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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// KSI service response payload.
    /// </summary>
    public abstract class ResponsePayload : PduPayload
    {
        private StringTag _errorMessage;
        private IntegerTag _status;

        /// <summary>
        ///     Create response payload TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        protected ResponsePayload(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.PduPayload.StatusTagType:
                    return _status = GetIntegerTag(childTag);
                case Constants.PduPayload.ErrorMessageTagType:
                    return _errorMessage = GetStringTag(childTag);
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

            if (tagCounter[Constants.PduPayload.StatusTagType] != 1)
            {
                throw new TlvException("Exactly one status code must exist in response payload.");
            }

            if (tagCounter[Constants.PduPayload.ErrorMessageTagType] > 1)
            {
                throw new TlvException("Only one error message is allowed in response payload.");
            }
        }

        /// <summary>
        ///     Get status code.
        /// </summary>
        public ulong Status => _status.Value;

        /// <summary>
        ///     Get error message if it exists.
        /// </summary>
        public string ErrorMessage => _errorMessage?.Value;
    }
}