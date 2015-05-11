using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class CertificateRecord : CompositeTag
    {
        private RawTag _certificateId;

        private RawTag _x509Certificate;

        public CertificateRecord(ITlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x1:
                        Value[i] = _certificateId = new RawTag(Value[i]);
                        break;
                    case 0x2:
                        Value[i] = _x509Certificate = new RawTag(Value[i]);
                        break;
                }
            }
        }
    }
}