using System;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     Publications file exception.
    /// </summary>
    public class PublicationsFileStructureException : KsiException
    {
        /// <summary>
        ///     Create new publications file structure exception with message
        /// </summary>
        /// <param name="message">Exception message</param>
        public PublicationsFileStructureException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new publications file structure exception with message and inner exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="innerException">Inner exception</param>
        public PublicationsFileStructureException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}