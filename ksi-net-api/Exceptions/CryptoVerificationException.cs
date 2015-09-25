using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     Crypto signature verification exception.
    /// </summary>
    public class CryptoVerificationException : KsiException
    {
        /// <summary>
        ///     Create new crypto signature verification exception with message.
        /// </summary>
        /// <param name="message">exception message</param>
        public CryptoVerificationException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new crypto signature verification exception  with message and inner exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="innerException">inner exception</param>
        public CryptoVerificationException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}