using System.Collections.Generic;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using System.IO;
using System;
using System.Collections.ObjectModel;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Signature
{
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

        public CalendarHashChain CalendarHashChain {
            get
            {
                return _ksiSignatureDo.CalendarHashChain;
            }
        }

        /// <summary>
        /// Create KSI signature instance
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

        // TODO: Should be public?
        private KsiSignature(KsiSignatureDo ksiSignatureDo)
        {
            if (ksiSignatureDo == null)
            {
                throw new ArgumentNullException("ksiSignatureDo");
            }
            _ksiSignatureDo = ksiSignatureDo;
        }

        /// <summary>
        /// Extend KSI signature
        /// </summary>
        /// <param name="calendarHashChain">Calendar hash chain</param>
        /// <returns>Extended KSI signature</returns>
        public KsiSignature Extend(CalendarHashChain calendarHashChain)
        {
            if (calendarHashChain == null)
            {
                throw new ArgumentNullException("calendarHashChain");
            }

            List<TlvTag> signatureTags = new List<TlvTag>();
            for (int i = 0; i < _ksiSignatureDo.Count; i++)
            {
                // TODO: Change type to constant
                if (_ksiSignatureDo[i].Type == CalendarAuthenticationRecord.TagType)
                {
                    signatureTags.Add(calendarHashChain);
                    continue;
                }

                signatureTags.Add(_ksiSignatureDo[i]);
            }

            return new KsiSignature(new KsiSignatureDo(signatureTags));
        }

        /// <summary>
        /// Get KSI signature instance
        /// </summary>
        /// <param name="stream">Signature data stream</param>
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

        public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
        {
            return _ksiSignatureDo.GetAggregationHashChains();
        }

        /// <summary>
        /// Get aggregation hash chain output hash
        /// </summary>
        /// <returns></returns>
        public DataHash GetAggregationHashChainRootHash()
        {
            return _ksiSignatureDo.GetAggregationHashChainRootHash();
        }

        /// <summary>
        /// Convert signature to string format
        /// </summary>
        /// <returns>Signature string representation</returns>
        public override string ToString()
        {
            return _ksiSignatureDo.ToString();
        }
    }
}
