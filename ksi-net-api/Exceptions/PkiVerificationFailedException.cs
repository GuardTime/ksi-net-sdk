using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     PKI signature verification failed exception.
    /// </summary>
    [Serializable]
    public class PkiVerificationFailedException : PkiVerificationException
    {
        /// <summary>
        ///     Create new PKI signature verification failed exception with message.
        /// </summary>
        /// <param name="message">exception message</param>
        public PkiVerificationFailedException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new PKI signature verification failed exception with message and inner exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="innerException">inner exception</param>
        public PkiVerificationFailedException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}