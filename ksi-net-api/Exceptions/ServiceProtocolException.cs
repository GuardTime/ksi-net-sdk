using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    /// KSI API base exception
    /// </summary>
    public class ServiceProtocolException : KsiException
    {
        /// <summary>
        /// Create new KSI exception
        /// </summary>
        /// <param name="message">Exception message</param>
        public ServiceProtocolException(string message) : base(message)
        {
        }

        /// <summary>
        /// Create new KSI exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="innerException">Inner exception</param>
        public ServiceProtocolException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
