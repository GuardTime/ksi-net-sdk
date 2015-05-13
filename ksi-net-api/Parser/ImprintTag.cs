using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Parser
{
    public class ImprintTag : TlvTag
    {
        public new DataHash Value;

        public ImprintTag(byte[] bytes) : base(bytes)
        {
            DecodeValue(base.EncodeValue());
        }

        public ImprintTag(TlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        public void DecodeValue(byte[] bytes)
        {
            Value = new DataHash(bytes);
        }

        public override byte[] EncodeValue()
        {
            return Value.Imprint;
        }

        public override bool Equals(object obj)
        {
            var tag = obj as ImprintTag;
            if (tag == null)
            {
                return false;
            }

            return tag.Type == Type &&
                   tag.Forward == Forward &&
                   tag.NonCritical == NonCritical &&
                   tag.Value.Equals(Value);
        }

    }

}
