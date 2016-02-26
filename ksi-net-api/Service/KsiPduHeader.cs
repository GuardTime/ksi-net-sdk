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
    ///     KSI PDU header.
    /// </summary>
    public sealed class KsiPduHeader : CompositeTag
    {
        private readonly IntegerTag _instanceId;
        private readonly StringTag _loginId;
        private readonly IntegerTag _messageId;

        /// <summary>
        ///     Create KSI PDU header from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public KsiPduHeader(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.KsiPduHeader.TagType)
            {
                throw new TlvException("Invalid KSI PDU header type(" + Type + ").");
            }

            int loginIdCount = 0;
            int instanceIdCount = 0;
            int messageIdCount = 0;

            foreach (ITlvTag childTag in this)
            {
                switch (childTag.Type)
                {
                    case Constants.KsiPduHeader.LoginIdTagType:
                        _loginId = new StringTag(childTag);
                        loginIdCount++;
                        break;
                    case Constants.KsiPduHeader.InstanceIdTagType:
                        _instanceId = new IntegerTag(childTag);
                        instanceIdCount++;
                        break;
                    case Constants.KsiPduHeader.MessageIdTagType:
                        _messageId = new IntegerTag(childTag);
                        messageIdCount++;
                        break;
                    default:
                        VerifyUnknownTag(childTag);
                        break;
                }
            }

            if (loginIdCount != 1)
            {
                throw new TlvException("Only one login id must exist in KSI PDU header.");
            }

            if (instanceIdCount > 1)
            {
                throw new TlvException("Only one instance id is allowed in KSI PDU header.");
            }

            if (messageIdCount > 1)
            {
                throw new TlvException("Only one message id is allowed in KSI PDU header.");
            }
        }

        /// <summary>
        ///     Create KSI PDU header from login ID.
        /// </summary>
        /// <param name="loginId">login ID</param>
        public KsiPduHeader(string loginId) : this(loginId, 0, 0)
        {
        }

        /// <summary>
        ///     Create KSI PDU header from login ID, instance ID, message ID.
        /// </summary>
        /// <param name="loginId">login ID</param>
        /// <param name="instanceId">instance ID</param>
        /// <param name="messageId">message ID</param>
        public KsiPduHeader(string loginId, ulong instanceId, ulong messageId)
            : base(Constants.KsiPduHeader.TagType, false, false, new ITlvTag[]
            {
                new StringTag(Constants.KsiPduHeader.LoginIdTagType, false, false, loginId),
                new IntegerTag(Constants.KsiPduHeader.InstanceIdTagType, false, false, instanceId),
                new IntegerTag(Constants.KsiPduHeader.MessageIdTagType, false, false, messageId)
            })
        {
            _loginId = (StringTag)this[0];
            _instanceId = (IntegerTag)this[1];
            _messageId = (IntegerTag)this[2];
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