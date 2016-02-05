using System.Collections.ObjectModel;
using System.IO;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     KSI signature interface.
    /// </summary>
    public interface IKsiSignature : ITlvTag
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
        PublicationRecordInSignature PublicationRecord { get; }

        /// <summary>
        ///     Get aggregation time.
        /// </summary>
        ulong AggregationTime { get; }

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
        ///     Extend KSI signature with given calendar hash chain.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <returns>extended KSI signature</returns>
        IKsiSignature Extend(CalendarHashChain calendarHashChain);

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <param name="publicationRecord">extended publication record</param>
        /// <returns>extended KSI signature</returns>
        IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInPublicationFile publicationRecord);

        /// <summary>
        ///     Extend signature to publication.
        /// </summary>
        /// <param name="calendarHashChain">extended calendar hash chain</param>
        /// <param name="publicationRecord">extended publication record</param>
        /// <returns>extended KSI signature</returns>
        IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecordInSignature publicationRecord);

        /// <summary>
        ///     Write KSI signature to stream.
        /// </summary>
        /// <param name="outputStream">output stream</param>
        void WriteTo(Stream outputStream);
    }
}