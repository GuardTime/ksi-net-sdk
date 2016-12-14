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
    /// PDU header.
    /// </summary>
    public sealed class PduHeader : CompositeTag
    {
        private IntegerTag _instanceId;
        private StringTag _loginId;
        private IntegerTag _messageId;

        /// <summary>
        /// Expected tag type
        /// </summary>
        protected override uint ExpectedTagType => Constants.PduHeader.TagType;

        /// <summary>
        ///     Create PDU header from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public PduHeader(ITlvTag tag) : base(tag)
        {
        }

        /// <summary>
        /// Parse child tag
        /// </summary>
        protected override ITlvTag ParseChild(ITlvTag childTag)
        {
            switch (childTag.Type)
            {
                case Constants.PduHeader.LoginIdTagType:
                    return _loginId = GetStringTag(childTag);
                case Constants.PduHeader.InstanceIdTagType:
                    return _instanceId = GetIntegerTag(childTag);
                case Constants.PduHeader.MessageIdTagType:
                    return _messageId = GetIntegerTag(childTag);
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

            if (tagCounter[Constants.PduHeader.LoginIdTagType] != 1)
            {
                throw new TlvException("Exactly one login id must exist in PDU header.");
            }

            if (tagCounter[Constants.PduHeader.InstanceIdTagType] > 1)
            {
                throw new TlvException("Only one instance id is allowed in PDU header.");
            }

            if (tagCounter[Constants.PduHeader.MessageIdTagType] > 1)
            {
                throw new TlvException("Only one message id is allowed in PDU header.");
            }
        }

        /// <summary>
        ///     Create PDU header from login ID.
        /// </summary>
        /// <param name="loginId">login ID</param>
        public PduHeader(string loginId) : this(loginId, 0, 0)
        {
        }

        /// <summary>
        ///     Create PDU header from login ID, instance ID, message ID.
        /// </summary>
        /// <param name="loginId">login ID</param>
        /// <param name="instanceId">instance ID</param>
        /// <param name="messageId">message ID</param>
        public PduHeader(string loginId, ulong instanceId, ulong messageId)
            : base(Constants.PduHeader.TagType, false, false, new ITlvTag[]
            {
                new StringTag(Constants.PduHeader.LoginIdTagType, false, false, loginId),
                new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, instanceId),
                new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, messageId)
            })
        {
        }

        /// <summary>
        ///     Get login ID.
        /// </summary>
        public string LoginId => _loginId.Value;

        /// <summary>
        ///     Get instance ID if it exists.
        /// </summary>
        public ulong? InstanceId => _instanceId?.Value;

        /// <summary>
        ///     Get message ID if it exists.
        /// </summary>
        public ulong? MessageId => _messageId?.Value;
    }
}