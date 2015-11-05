using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     KSI service protocol exception.
    /// </summary>
    [Serializable]
    public class KsiServiceProtocolException : KsiException
    {
        /// <summary>
        ///     Create new KSI service protocol exception.
        /// </summary>
        /// <param name="message">Exception message</param>
        public KsiServiceProtocolException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new KSI service protocol exception.
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="innerException">Inner exception</param>
        public KsiServiceProtocolException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}