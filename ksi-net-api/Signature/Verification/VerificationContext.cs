using System;
using System.Collections.ObjectModel;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification
{
    /// <summary>
    /// Verification context.
    /// </summary>
    public class VerificationContext : IVerificationContext
    {
        private KsiSignature _signature;
        private DataHash _documentHash;

        /// <summary>
        /// Get or set document hash.
        /// </summary>
        public DataHash DocumentHash
        {
            get
            {
                return _documentHash;
            }

            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }

                _documentHash = value;
            }
        }

        /// <summary>
        /// Get calendar hash chain.
        /// </summary>
        public CalendarHashChain CalendarHashChain
        {
            get
            {
                return _signature == null ? null : _signature.CalendarHashChain;
            }
        }

        /// <summary>
        /// Get calendar authentication record.
        /// </summary>
        public CalendarAuthenticationRecord CalendarAuthenticationRecord
        {
            get
            {
                return _signature == null ? null : _signature.CalendarAuthenticationRecord;
            }
        }

        /// <summary>
        /// Get publication record.
        /// </summary>
        public PublicationRecord PublicationRecord
        {
            get
            {
                return _signature == null ? null : _signature.PublicationRecord;
            }
        }

        /// <summary>
        /// Get or set KSI signature.
        /// </summary>
        public KsiSignature Signature
        {
            get
            {
                return _signature;
            }

            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }

                _signature = value;
            }
        }

        /// <summary>
        /// Get aggregation hash chains collection.
        /// </summary>
        /// <returns>aggregation hash chains collection</returns>
        public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
        {
            return _signature == null ? null : _signature.GetAggregationHashChains();
        }

        /// <summary>
        /// Get aggregation hash chains root hash
        /// </summary>
        /// <returns>output hash</returns>
        public DataHash GetAggregationHashChainRootHash()
        {
            return _signature == null ? null : _signature.GetAggregationHashChainRootHash();
        }

    }
}