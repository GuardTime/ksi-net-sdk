using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Service
{
    public sealed class KsiPduHeader : CompositeTag
    {
        // TODO: Better name
        public const uint TagType = 0x1;
        private const uint LoginIdTagType = 0x1;
        private const uint InstanceIdTagType = 0x2;
        private const uint MessageIdTagType = 0x3;

        private readonly StringTag _loginId;
        private readonly IntegerTag _instanceId;
        private readonly IntegerTag _messageId;

        public KsiPduHeader(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid ksi pdu header type: " + Type);
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
                        VerifyCriticalTag(this[i]);
                        break;
                }
            }

            if (loginIdCount != 1)
            {
                throw new InvalidTlvStructureException("Only one login id must exist in ksi pdu header");
            }

            if (instanceIdCount > 1)
            {
                throw new InvalidTlvStructureException("Only one instance id is allowed in ksi pdu header");
            }

            if (messageIdCount > 1)
            {
                throw new InvalidTlvStructureException("Only one message id is allowed in ksi pdu header");
            }
        }
        
        public KsiPduHeader(string loginId) : this(loginId, 0, 0)
        {
        }

        public KsiPduHeader(string loginId, ulong instanceId, ulong messageId) : base(TagType, false, false, new List<TlvTag>())
        {
            _loginId = new StringTag(LoginIdTagType, false, false, loginId);
            AddTag(_loginId);

            _instanceId = new IntegerTag(InstanceIdTagType, false, false, instanceId);
            AddTag(_instanceId);

            _messageId = new IntegerTag(MessageIdTagType, false, false, messageId);
            AddTag(_messageId);
        }
    }
}
