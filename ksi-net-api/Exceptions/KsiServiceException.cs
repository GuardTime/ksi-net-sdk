using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     KSI service exception.
    /// </summary>
    public class KsiServiceException : KsiException
    {
        /// <summary>
        ///     Create new KSI service exception.
        /// </summary>
        /// <param name="message">Exception message</param>
        public KsiServiceException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new KSI service exception.
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="innerException">Inner exception</param>
        public KsiServiceException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}