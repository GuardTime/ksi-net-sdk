using System;
using System.Collections.ObjectModel;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Signature.Verification
{
    public class VerificationContext : IVerificationContext
    {
        private KsiSignature _signature;
        private DataHash _documentHash;

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

        public CalendarHashChain CalendarHashChain
        {
            get
            {
                return _signature == null ? null : _signature.CalendarHashChain;
            }
        }

        public CalendarAuthenticationRecord CalendarAuthenticationRecord
        {
            get
            {
                return _signature == null ? null : _signature.CalendarAuthenticationRecord;
            }
        }

        public PublicationRecord PublicationRecord
        {
            get
            {
                return _signature == null ? null : _signature.PublicationRecord;
            }
        }

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

        

        public ReadOnlyCollection<AggregationHashChain> GetAggregationHashChains()
        {
            return _signature == null ? null : _signature.GetAggregationHashChains();
        }

        public DataHash GetAggregationHashChainRootHash()
        {
            return _signature == null ? null : _signature.GetAggregationHashChainRootHash();
        }

    }
}