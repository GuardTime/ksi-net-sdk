using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    public class ExtendError : ExtendPduPayload
    {
        // TODO: Better name
        public const uint TagType = 0x303;

        private readonly IntegerTag _status;
        private readonly StringTag _errorMessage;

        public ExtendError(TlvTag tag) : base(tag)
        {
            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case StatusTagType:
                        _status = new IntegerTag(this[i]);
                        this[i] = _status;
                        break;
                    case ErrorMessageTagType:
                        _errorMessage = new StringTag(this[i]);
                        this[i] = _errorMessage;
                        break;
                }
            }
        }

        protected override void CheckStructure()
        {
            throw new NotImplementedException();
        }

    }
}
