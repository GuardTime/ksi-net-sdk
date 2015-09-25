using System;

namespace Guardtime.KSI.Exceptions
{
    [Serializable]
    internal class HashingException : KsiException
    {
        public HashingException(string message) : base(message)
        {
        }

        public HashingException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}