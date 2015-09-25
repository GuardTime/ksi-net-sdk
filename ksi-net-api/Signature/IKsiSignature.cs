using System.Collections.ObjectModel;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    public interface IKsiSignature
    {
        /// <summary>
        ///     Get RFC 3161 record
        /// </summary>
        Rfc3161Record Rfc3161Record { get; }

        /// <summary>
        ///     Is signature RFC 3161 format
        /// </summary>
        bool IsRfc3161Signature { get; }

        /// <summary>
        ///     Get calendar hash chain.
        /// </summary>
        CalendarHashChain CalendarHashChain { get; }

        /// <summary>
        ///     Get calendar authentication record.
        /// </summary>
        CalendarAuthenticationRecord CalendarAuthenticationRecord { get; }

        /// <summary>
        ///     Get publication record.
        /// </summary>
        PublicationRecord PublicationRecord { get; }

        /// <summary>
        ///     Get aggregation hash chains list.
        /// </summary>
        /// <returns>aggregations hash chains list</returns>
        ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains();

        /// <summary>
        ///     Get aggregation hash chain output hash.
        /// </summary>
        /// <returns>output hash</returns>
        DataHash GetAggregationHashChainRootHash();

        /// <summary>
        /// Get aggregation time.
        /// </summary>
        ulong AggregationTime { get; }

        /// <summary>
        /// Extend KSI signature with given calendar hash chain.
        /// </summary>
        /// <param name="calendarHashChain">calendar hash chain</param>
        /// <returns>extended KSI signature</returns>
        IKsiSignature Extend(CalendarHashChain calendarHashChain);
        
    }
}