using System.Collections.Generic;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class KsiSignature
    {
        private KsiSignatureDo _ksiSignatureDo;

        // TODO: Create interface for tags list
        public KsiSignature(CompositeTag response)
        {
            List<TlvTag> signatureTags = new List<TlvTag>();
            List<TlvTag> tlvTags = response.Value;
            for (int i = 0; i < tlvTags.Count; i++)
            {
                if (tlvTags[i].Type > 0x800 && tlvTags[i].Type < 0x900)
                {
                    signatureTags.Add(tlvTags[i]);
                }
            }

            _ksiSignatureDo = new KsiSignatureDo(signatureTags);
            _ksiSignatureDo.IsValidStructure();
        }

        public override string ToString()
        {
            return _ksiSignatureDo.ToString();
        }
    }
}
