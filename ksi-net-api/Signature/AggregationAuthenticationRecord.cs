using Guardtime.KSI.Parser;
using System.Collections.Generic;

namespace Guardtime.KSI.Signature
{
    public class AggregationAuthenticationRecord : ICompositeTag
    {

        private IntegerTag _aggregationTime;

        private List<IntegerTag> _chainIndex;

        private ImprintTag _inputHash;

        private CompositeTag<SignatureData> _signatureData;

        public ITlvTag GetMember(ITlvTag tag)
        {
            switch (tag.Type)
            {
                case 0x2:
                    _aggregationTime = new IntegerTag(tag);
                    return _aggregationTime;
                case 0x3:
                    if (_chainIndex == null)
                    {
                        _chainIndex = new List<IntegerTag>();
                    }

                    var chainIndexTag = new IntegerTag(tag);
                    _chainIndex.Add(chainIndexTag);
                    return chainIndexTag;
                case 0x5:
                    _inputHash = new ImprintTag(tag);
                    return _inputHash;
                case 0xB:
                    _signatureData = new CompositeTag<SignatureData>(tag, new SignatureData());
                    return _signatureData;

            }

            return null;
        }
    }
}