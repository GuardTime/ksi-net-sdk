using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     Hashing functionality exception.
    /// </summary>
    [Serializable]
    public class HashingException : KsiException
    {
        /// <summary>
        ///     Create new hashing exception with message.
        /// </summary>
        /// <param name="message">exception message</param>
        public HashingException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new hashing exception  with message and inner exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="innerException">inner exception</param>
        public HashingException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}