using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    ///     KSI signature factory.
    /// </summary>
    public partial class KsiSignatureFactory
    {
        /// <summary>
        ///     KSI Signature implementation.
        /// </summary>
        private sealed class KsiSignature : CompositeTag, IKsiSignature
        {
            private readonly List<AggregationHashChain> _aggregationHashChainCollection =
                new List<AggregationHashChain>();

            /// <summary>
            ///     Create new KSI signature TLV element from TLV element.
            /// </summary>
            /// <param name="tag">TLV element</param>
            public KsiSignature(ITlvTag tag) : base(tag)
            {
                if (Type != Constants.KsiSignature.TagType)
                {
                    throw new TlvException("Invalid KSI signature type(" + Type + ").");
                }

                int calendarChainCount = 0;
                int publicationRecordCount = 0;
                int aggregationAuthenticationRecordCount = 0;
                int calendarAuthenticationRecordCount = 0;
                int rfc3161RecordCount = 0;

                for (int i = 0; i < Count; i++)
                {
                    switch (this[i].Type)
                    {
                        case Constants.AggregationHashChain.TagType:
                            AggregationHashChain aggregationChainTag = new AggregationHashChain(this[i]);
                            _aggregationHashChainCollection.Add(aggregationChainTag);
                            break;
                        case Constants.CalendarHashChain.TagType:
                            CalendarHashChain = new CalendarHashChain(this[i]);
                            calendarChainCount++;
                            break;
                        case Constants.PublicationRecord.TagTypeSignature:
                            PublicationRecord = new PublicationRecord(this[i]);
                            publicationRecordCount++;
                            break;
                        case Constants.AggregationAuthenticationRecord.TagType:
                            AggregationAuthenticationRecord = new AggregationAuthenticationRecord(this[i]);
                            aggregationAuthenticationRecordCount++;
                            break;
                        case Constants.CalendarAuthenticationRecord.TagType:
                            CalendarAuthenticationRecord = new CalendarAuthenticationRecord(this[i]);
                            calendarAuthenticationRecordCount++;
                            break;
                        case Constants.Rfc3161Record.TagType:
                            Rfc3161Record = new Rfc3161Record(this[i]);
                            rfc3161RecordCount++;
                            break;
                        default:
                            VerifyUnknownTag(this[i]);
                            break;
                    }
                }

                if (_aggregationHashChainCollection.Count == 0)
                {
                    throw new TlvException("Aggregation hash chains must exist in KSI signature.");
                }

                if (calendarChainCount > 1)
                {
                    throw new TlvException(
                        "Only one calendar hash chain is allowed in KSI signature.");
                }

                if (calendarChainCount == 0 && (publicationRecordCount != 0 || calendarAuthenticationRecordCount != 0))
                {
                    throw new TlvException(
                        "No publication record or calendar authentication record is allowed in KSI signature if there is no calendar hash chain.");
                }

                if ((publicationRecordCount == 1 && calendarAuthenticationRecordCount == 1) ||
                    publicationRecordCount > 1 ||
                    calendarAuthenticationRecordCount > 1)
                {
                    throw new TlvException(
                        "Only one from publication record or calendar authentication record is allowed in KSI signature.");
                }

                if (aggregationAuthenticationRecordCount > 1)
                {
                    throw new TlvException(
                        "Only one aggregation authentication record is allowed in KSI signature.");
                }

                if (rfc3161RecordCount > 1)
                {
                    throw new TlvException(
                        "Only one RFC 3161 record is allowed in KSI signature.");
                }

                _aggregationHashChainCollection.Sort(new AggregationHashChain.ChainIndexOrdering());
            }

            /// <summary>
            ///     Get aggregation authentication record if it exists.
            /// </summary>
            public AggregationAuthenticationRecord AggregationAuthenticationRecord { get; }

            /// <summary>
            ///     Get RFC 3161 record
            /// </summary>
            public Rfc3161Record Rfc3161Record { get; }

            /// <summary>
            ///     Is signature RFC 3161 format
            /// </summary>
            public bool IsRfc3161Signature => Rfc3161Record != null;

            /// <summary>
            ///     Get calendar hash chain.
            /// </summary>
            public CalendarHashChain CalendarHashChain { get; }

            /// <summary>
            ///     Get calendar authentication record.
            /// </summary>
            public CalendarAuthenticationRecord CalendarAuthenticationRecord { get; }

            /// <summary>
            ///     Get publication record.
            /// </summary>
            public PublicationRecord PublicationRecord { get; }

            /// <summary>
            ///     Get aggregation hash chains list.
            /// </summary>
            /// <returns>aggregations hash chains list</returns>
            public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
            {
                return _aggregationHashChainCollection.AsReadOnly();
            }

            /// <summary>
            ///     Get aggregation hash chain output hash.
            /// </summary>
            /// <returns>output hash</returns>
            public DataHash GetAggregationHashChainRootHash()
            {
                // Store result
                AggregationHashChainResult lastResult = new AggregationHashChainResult(0,
                    _aggregationHashChainCollection[0].InputHash);
                for (int i = 0; i < _aggregationHashChainCollection.Count; i++)
                {
                    lastResult = _aggregationHashChainCollection[i].GetOutputHash(lastResult);
                }

                return lastResult.Hash;
            }

            /// <summary>
            ///     Get aggregation time.
            /// </summary>
            public ulong AggregationTime => _aggregationHashChainCollection[0].AggregationTime;

            /// <summary>
            ///     Extend KSI signature with given calendar hash chain.
            /// </summary>
            /// <param name="calendarHashChain">calendar hash chain</param>
            /// <returns>extended KSI signature</returns>
            public IKsiSignature Extend(CalendarHashChain calendarHashChain)
            {
                return Extend(calendarHashChain, null);
            }

            /// <summary>
            ///     Extend signature to publication.
            /// </summary>
            /// <param name="calendarHashChain">extended calendar hash chain</param>
            /// <param name="publicationRecord">extended publication record</param>
            /// <returns>extended KSI signature</returns>
            public IKsiSignature Extend(CalendarHashChain calendarHashChain, PublicationRecord publicationRecord)
            {
                if (calendarHashChain == null)
                {
                    throw new KsiException("Invalid calendar hash chain: null.");
                }

                using (TlvWriter writer = new TlvWriter(new MemoryStream()))
                {
                    for (int i = 0; i < Count; i++)
                    {
                        switch (this[i].Type)
                        {
                            case Constants.CalendarHashChain.TagType:
                                writer.WriteTag(calendarHashChain);
                                break;
                            case Constants.PublicationRecord.TagTypeSignature:
                                if (publicationRecord != null)
                                {
                                    writer.WriteTag(publicationRecord);
                                }
                                break;
                            default:
                                writer.WriteTag(this[i]);
                                break;
                        }
                    }

                    return
                        new KsiSignature(new RawTag(Constants.KsiSignature.TagType, false, false,
                            ((MemoryStream)writer.BaseStream).ToArray()));
                }
            }

            /// <summary>
            ///     Write KSI signature to stream.
            /// </summary>
            /// <param name="outputStream">output stream</param>
            public void WriteTo(Stream outputStream)
            {
                if (outputStream == null)
                {
                    throw new KsiException("Invalid output stream: null.");
                }

                if (!outputStream.CanWrite)
                {
                    throw new KsiException("Output stream is not writable.");
                }

                using (TlvWriter writer = new TlvWriter(outputStream))
                {
                    writer.WriteTag(this);
                }
            }
        }
    }
}