using System;

namespace Guardtime.KSI.Exceptions
{
    class KsiException : Exception
    {
        public KsiException(string message) : base(message)
        {
        }

        public KsiException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
