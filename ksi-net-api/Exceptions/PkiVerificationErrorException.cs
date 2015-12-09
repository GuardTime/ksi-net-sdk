using System;
using System.Collections.Generic;
using System.Text;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     PKI signature verification error exception.
    /// </summary>
    [Serializable]
    public class PkiVerificationErrorException : PkiVerificationException
    {
        /// <summary>
        ///     Create new PKI signature verification error exception with message.
        /// </summary>
        /// <param name="message">exception message</param>
        public PkiVerificationErrorException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new PKI signature verification error exception with message and inner exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="innerException">inner exception</param>
        public PkiVerificationErrorException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}