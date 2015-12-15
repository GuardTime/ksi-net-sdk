using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     TLV exception.
    /// </summary>
    [Serializable]
    public class TlvException : KsiException
    {
        /// <summary>
        ///     Create new TlvException exception.
        /// </summary>
        /// <param name="message">exception message</param>
        public TlvException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new TlvException exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="innerException">inner exception</param>
        public TlvException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}