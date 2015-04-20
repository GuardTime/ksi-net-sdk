using System;

namespace Guardtime.KSI.Hashing
{
    class HashingException : Exception
    {

        public HashingException(string message) : base(message)
        {
        }

        public HashingException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
