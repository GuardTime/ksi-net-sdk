using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     KSI API base exception
    /// </summary>
    [Serializable]
    public class KsiException : Exception
    {
        /// <summary>
        ///     Create new KSI exception
        /// </summary>
        /// <param name="message">Exception message</param>
        public KsiException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new KSI exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="innerException">Inner exception</param>
        public KsiException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}