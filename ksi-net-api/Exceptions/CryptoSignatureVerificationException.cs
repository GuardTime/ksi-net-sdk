using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     PKI signature verification exception.
    /// </summary>
    [Serializable]
    public class CryptoSignatureVerificationException : KsiException
    {
        /// <summary>
        ///     Create new PKI signature verification exception with message.
        /// </summary>
        /// <param name="message">exception message</param>
        public CryptoSignatureVerificationException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new PKI signature verification exception  with message and inner exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="innerException">inner exception</param>
        public CryptoSignatureVerificationException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}