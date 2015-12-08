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
        public AggregationErrorPayload(ITlvTag tag) : base(tag, Constants.AggregationErrorPayload.TagType)
        {
        }
    }
}