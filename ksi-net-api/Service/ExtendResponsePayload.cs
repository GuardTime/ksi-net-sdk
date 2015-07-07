using System;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    public class ExtendResponsePayload : ExtendPduPayload
    {
        // TODO: Better name
        public const uint TagType = 0x302;
        private const uint RequestIdTagType = 0x1;
        private const uint LastTimeTagType = 0x10;

        private readonly IntegerTag _requestId;
        private readonly IntegerTag _status;
        private readonly StringTag _errorMessage;

        private readonly IntegerTag _lastTime;

        private readonly CalendarHashChain _calendarHashChain;

        public CalendarHashChain CalendarHashChain
        {
            get
            {
                return _calendarHashChain;
            }
        }

        public ExtendResponsePayload(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case RequestIdTagType:
                        _requestId = new IntegerTag(this[i]);
                        this[i] = _requestId;
                        break;
                    case StatusTagType:
                        _status = new IntegerTag(this[i]);
                        this[i] = _status;
                        break;
                    case ErrorMessageTagType:
                        _errorMessage = new StringTag(this[i]);
                        this[i] = _errorMessage;
                        break;
                    case LastTimeTagType:
                        _lastTime = new IntegerTag(this[i]);
                        this[i] = _lastTime;
                        break;
                    case CalendarHashChain.TagType:
                        _calendarHashChain = new CalendarHashChain(this[i]);
                        this[i] = _calendarHashChain;
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            // TODO: Check structure
        }

    }
}
