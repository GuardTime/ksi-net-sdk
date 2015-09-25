using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     KSI signature verification exception.
    /// </summary>
    public class KsiVerificationException : KsiException
    {
        /// <summary>
        ///     Create new KSI verification exception with message.
        /// </summary>
        /// <param name="message">exception message</param>
        public KsiVerificationException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new KSI verification exception  with message and inner exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="innerException">inner exception</param>
        public KsiVerificationException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}