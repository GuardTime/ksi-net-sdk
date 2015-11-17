using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregation Error payload TLV element.
    /// </summary>
    public sealed class AggregationErrorPayload : ErrorPayload
    {

        /// <summary>
        ///     Create aggregation error payload TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public AggregationErrorPayload(ITlvTag tag) : base(tag, Constants.AggregationErrorPayload.TagType)
        {
        }
    }
}