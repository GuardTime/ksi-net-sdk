using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using System.IO;
using System;
using System.Collections.ObjectModel;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// KSI signature.
    /// </summary>
    public sealed class KsiSignature
    {
        private readonly KsiSignatureDo _ksiSignatureDo;

        /// <summary>
        /// Is signature in RFC 3161 format
        /// </summary>
        public bool IsRfc3161Signature
        {
            get
            {
                return _ksiSignatureDo.IsRfc3161Signature;
            }
        }

        /// <summary>
        /// Get RFC 3161 record
        /// </summary>
        public Rfc3161Record Rfc3161Record
        {
            get
            {
                return _ksiSignatureDo.Rfc3161Record;
            }
        }

        /// <summary>
        /// Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain {
            get
            {
                return _ksiSignatureDo.CalendarHashChain;
            }
        }

        /// <summary>
        /// Get calendar authentication record.
        /// </summary>
        public CalendarAuthenticationRecord CalendarAuthenticationRecord
        {
            get
            {
                return _ksiSignatureDo.CalendarAuthenticationRecord;
            }
        }

        /// <summary>
        /// Get publication record.
        /// </summary>
        public PublicationRecord PublicationRecord
        {
            get
            {
                return _ksiSignatureDo.PublicationRecord;
            }
        }

        /// <summary>
        /// Get aggregation time.
        /// </summary>
        public ulong AggregationTime
        {
            get { return _ksiSignatureDo.GetAggregationHashChains()[0].AggregationTime; }
        }

        /// <summary>
        /// Create KSI signature instance from KSI PDU payload.
        /// </summary>
        /// <param name="response">KSI PDU payload</param>
        public KsiSignature(KsiPduPayload response)
        {
            List<TlvTag> signatureTags = new List<TlvTag>();
            for (int i = 0; i < response.Count; i++)
            {
                if (response[i].Type > 0x800 && response[i].Type < 0x900)
                {
                    signatureTags.Add(response[i]);
                }
            }

            // TODO: Make signature data object to interface
            _ksiSignatureDo = new KsiSignatureDo(signatureTags);
        }

        /// <summary>
        /// Create signature from signature data object.
        /// </summary>
        /// <param name="ksiSignatureDo">KSI signature data object</param>
        private KsiSignature(KsiSignatureDo ksiSignatureDo)
        {
            if (ksiSignatureDo == null)
            {
                throw new ArgumentNullException("ksiSignatureDo");
            }
            _ksiSignatureDo = ksiSignatureDo;
        }

        /// <summary>
        /// Extend KSI signature with given calendar hash chain.
        /// </summary>
        /// <param name="calendarHashChain">calendar hash chain</param>
        /// <returns>extended KSI signature</returns>
        public KsiSignature Extend(CalendarHashChain calendarHashChain)
        {
            if (calendarHashChain == null)
            {
                throw new ArgumentNullException("calendarHashChain");
            }

            List<TlvTag> signatureTags = new List<TlvTag>();
            for (int i = 0; i < _ksiSignatureDo.Count; i++)
            {
                if (_ksiSignatureDo[i].Type == CalendarHashChain.TagType)
                {
                    signatureTags.Add(calendarHashChain);
                    continue;
                }

                signatureTags.Add(_ksiSignatureDo[i]);
            }

            return new KsiSignature(new KsiSignatureDo(signatureTags));
        }

        /// <summary>
        /// Get KSI signature instance from stream.
        /// </summary>
        /// <param name="stream">signature data stream</param>
        /// <returns>KSI signature</returns>
        public static KsiSignature GetInstance(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            using (TlvReader reader = new TlvReader(stream))
            {
                return new KsiSignature(new KsiSignatureDo(reader.ReadTag()));
            }
        }

        /// <summary>
        /// Get aggregation hash chains.
        /// </summary>
        /// <returns>aggregation hash chains list</returns>
        public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
        {
            return _ksiSignatureDo.GetAggregationHashChains();
        }

        /// <summary>
        /// Get aggregation hash chain output hash.
        /// </summary>
        /// <returns>aggregation hash chain root hash</returns>
        public DataHash GetAggregationHashChainRootHash()
        {
            return _ksiSignatureDo.GetAggregationHashChainRootHash();
        }

        /// <summary>
        /// Convert signature to string format.
        /// </summary>
        /// <returns>signature string representation</returns>
        public override string ToString()
        {
            return _ksiSignatureDo.ToString();
        }
    }
}
