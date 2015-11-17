using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Extension error payload.
    /// </summary>
    public sealed class ExtendErrorPayload : ErrorPayload
    {
        /// <summary>
        ///     Create extend error payload from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public ExtendErrorPayload(TlvTag tag) : base(tag, Constants.ExtendErrorPayload.TagType)
        {
        }
    }
}