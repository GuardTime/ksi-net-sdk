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
        ///     KSI Signature implementation.
        /// </summary>
    public sealed class KsiSignature : CompositeTag, IKsiSignature
        {
        private readonly List<AggregationHashChain> _aggregationHashChains = new List<AggregationHashChain>();

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

            foreach (ITlvTag childTag in this)
                {
                switch (childTag.Type)
                    {
                        case Constants.AggregationHashChain.TagType:
                        AggregationHashChain aggregationChainTag = new AggregationHashChain(childTag);
                        _aggregationHashChains.Add(aggregationChainTag);
                            break;
                        case Constants.CalendarHashChain.TagType:
                        CalendarHashChain = new CalendarHashChain(childTag);
                            calendarChainCount++;
                            break;
                        case Constants.PublicationRecord.TagTypeSignature:
                        PublicationRecord = new PublicationRecord(childTag);
                            publicationRecordCount++;
                            break;
                        case Constants.AggregationAuthenticationRecord.TagType:
                        AggregationAuthenticationRecord = new AggregationAuthenticationRecord(childTag);
                            aggregationAuthenticationRecordCount++;
                            break;
                        case Constants.CalendarAuthenticationRecord.TagType:
                        CalendarAuthenticationRecord = new CalendarAuthenticationRecord(childTag);
                            calendarAuthenticationRecordCount++;
                            break;
                        case Constants.Rfc3161Record.TagType:
                        Rfc3161Record = new Rfc3161Record(childTag);
                            rfc3161RecordCount++;
                            break;
                        default:
                        VerifyUnknownTag(childTag);
                            break;
                    }
                }

            if (_aggregationHashChains.Count == 0)
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

            _aggregationHashChains.Sort(new AggregationHashChain.ChainIndexOrdering());
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
            return _aggregationHashChains.AsReadOnly();
            }

            /// <summary>
            ///     Get aggregation hash chain output hash.
            /// </summary>
            /// <returns>output hash</returns>
            public DataHash GetAggregationHashChainRootHash()
            {
                // Store result
            AggregationHashChainResult lastResult = new AggregationHashChainResult(0, _aggregationHashChains[0].InputHash);

            foreach (AggregationHashChain chain in _aggregationHashChains)
                {
                lastResult = chain.GetOutputHash(lastResult);
                }

                return lastResult.Hash;
            }

            /// <summary>
            ///     Get aggregation time.
            /// </summary>
        public ulong AggregationTime => _aggregationHashChains[0].AggregationTime;

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
                foreach (ITlvTag childTag in this)
                    {
                    switch (childTag.Type)
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
                            writer.WriteTag(childTag);
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
