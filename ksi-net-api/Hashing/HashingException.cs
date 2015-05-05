using System;
using System.Runtime.Serialization;

namespace Guardtime.KSI.Hashing
{
    [Serializable]
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
