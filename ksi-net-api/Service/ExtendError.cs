using System;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Service
{
    public sealed class ExtendError : ExtendPduPayload
    {
        // TODO: Better name
        public const uint TagType = 0x303;

        private readonly IntegerTag _status;
        private readonly StringTag _errorMessage;

        public ExtendError(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new InvalidTlvStructureException("Invalid extend error type: " + Type);
            }

            int statusCount = 0;
            int errorMessageCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case StatusTagType:
                        _status = new IntegerTag(this[i]);
                        this[i] = _status;
                        statusCount++;
                        break;
                    case ErrorMessageTagType:
                        _errorMessage = new StringTag(this[i]);
                        this[i] = _errorMessage;
                        errorMessageCount++;
                        break;
                    default:
                        VerifyCriticalTag(this[i]);
                        break;
                }
            }

            if (statusCount != 1)
            {
                throw new InvalidTlvStructureException("Only one status code must exist in extend error");
            }

            if (errorMessageCount > 1)
            {
                throw new InvalidTlvStructureException("Only one error message is allowed in extend error");
            }
        }

    }
}
