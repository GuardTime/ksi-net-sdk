using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    public class KsiPduHeader : CompositeTag
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
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case LoginIdTagType:
                        _loginId = new StringTag(this[i]);
                        this[i] = _loginId;
                        break;
                    case InstanceIdTagType:
                        _instanceId = new IntegerTag(this[i]);
                        this[i] = _instanceId;
                        break;
                    case MessageIdTagType:
                        _messageId = new IntegerTag(this[i]);
                        this[i] = _messageId;
                        break;
                }
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

        protected override void CheckStructure()
        {
            // TODO: Check structure
        }
    }
}
