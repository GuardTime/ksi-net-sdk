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
        public ExtendErrorPayload(ITlvTag tag) : base(tag, Constants.ExtendErrorPayload.TagType)
        {
        }
    }
}