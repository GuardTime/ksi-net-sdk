using System.Collections.Generic;
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
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public KsiPduHeader(ITlvTag tag) : base(tag)
        {
            if (Type != Constants.KsiPduHeader.TagType)
            {
                throw new TlvException("Invalid KSI PDU header type(" + Type + ").");
            }

            int loginIdCount = 0;
            int instanceIdCount = 0;
            int messageIdCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case Constants.KsiPduHeader.LoginIdTagType:
                        _loginId = new StringTag(this[i]);
                        loginIdCount++;
                        break;
                    case Constants.KsiPduHeader.InstanceIdTagType:
                        _instanceId = new IntegerTag(this[i]);
                        instanceIdCount++;
                        break;
                    case Constants.KsiPduHeader.MessageIdTagType:
                        _messageId = new IntegerTag(this[i]);
                        messageIdCount++;
                        break;
                    default:
                        VerifyUnknownTag(this[i]);
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
            : base(Constants.KsiPduHeader.TagType, false, false, new List<ITlvTag>()
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