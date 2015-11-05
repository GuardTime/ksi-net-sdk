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
        /// <summary>
        ///     KSI PDU header TLV type.
        /// </summary>
        public const uint TagType = 0x1;

        private const uint LoginIdTagType = 0x1;
        private const uint InstanceIdTagType = 0x2;
        private const uint MessageIdTagType = 0x3;

        private readonly IntegerTag _instanceId;
        private readonly StringTag _loginId;
        private readonly IntegerTag _messageId;

        /// <summary>
        ///     Create KSI PDU header from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public KsiPduHeader(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
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
                    case LoginIdTagType:
                        _loginId = new StringTag(this[i]);
                        this[i] = _loginId;
                        loginIdCount++;
                        break;
                    case InstanceIdTagType:
                        _instanceId = new IntegerTag(this[i]);
                        this[i] = _instanceId;
                        instanceIdCount++;
                        break;
                    case MessageIdTagType:
                        _messageId = new IntegerTag(this[i]);
                        this[i] = _messageId;
                        messageIdCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
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
            : base(TagType, false, false, new List<TlvTag>())
        {
            _loginId = new StringTag(LoginIdTagType, false, false, loginId);
            AddTag(_loginId);

            _instanceId = new IntegerTag(InstanceIdTagType, false, false, instanceId);
            AddTag(_instanceId);

            _messageId = new IntegerTag(MessageIdTagType, false, false, messageId);
            AddTag(_messageId);
        }

        /// <summary>
        ///     Get login ID.
        /// </summary>
        public string LoginId
        {
            get { return _loginId.Value; }
        }

        /// <summary>
        ///     Get instance ID if it exists.
        /// </summary>
        public ulong? InstanceId
        {
            get { return _instanceId == null ? (ulong?)null : _instanceId.Value; }
        }

        /// <summary>
        ///     Get message ID if it exists.
        /// </summary>
        public ulong? MessageId
        {
            get { return _messageId == null ? (ulong?)null : _messageId.Value; }
        }
    }
}