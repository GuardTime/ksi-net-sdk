using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     Invalid TLV exception.
    /// </summary>
    public class TlvException : KsiException
    {
        /// <summary>
        ///     Create new InvalidTlvStructure exception.
        /// </summary>
        /// <param name="message">exception message</param>
        public TlvException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new InvalidTlvStructure exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="innerException">inner exception</param>
        public TlvException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}