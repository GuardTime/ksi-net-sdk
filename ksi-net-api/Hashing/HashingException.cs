using System;

namespace Guardtime.KSI.Hashing
{
    [Serializable]
    class HashingException : System.Exception
    {

        public HashingException(string message) : base(message)
        {
        }

        public HashingException(string message, System.Exception innerException) : base(message, innerException)
        {
        }
    }
}
