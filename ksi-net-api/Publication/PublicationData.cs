using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Publication
{
    public class PublicationData : CompositeTag
    {
        public IntegerTag PublicationTime;
        public ImprintTag PublicationHash;

        public PublicationData(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                        PublicationTime = new IntegerTag(Value[i]);
                        Value[i] = PublicationTime;
                        break;
                    case 0x4:
                        PublicationHash = new ImprintTag(Value[i]);
                        Value[i] = PublicationHash;
                        break;
                }
            }
        }


        public override bool IsValidStructure()
        {
            throw new System.NotImplementedException();
        }
    }
}
