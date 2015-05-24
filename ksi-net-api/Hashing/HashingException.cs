using System;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Hashing
{
    [Serializable]
    class HashingException : KsiException
    {

        public HashingException(string message) : base(message)
        {
        }

        public HashingException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
