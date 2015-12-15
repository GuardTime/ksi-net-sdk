using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     Aggregation chain output result
    /// </summary>
    public class AggregationHashChainResult
    {
        /// <summary>
        ///     Create chain result from level and data hash.
        /// </summary>
        /// <param name="level">hash chain level</param>
        /// <param name="hash">output hash</param>
        public AggregationHashChainResult(ulong level, DataHash hash)
        {
            Level = level;
            Hash = hash;
        }

        /// <summary>
        ///     Get aggregation chain output hash
        /// </summary>
        public DataHash Hash { get; }

        /// <summary>
        ///     Get aggregation chain output hash level
        /// </summary>
        public ulong Level { get; }
    }
}