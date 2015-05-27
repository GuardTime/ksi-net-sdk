using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Parser
{
    public class ImprintTag : TlvTag
    {
        private readonly DataHash _value;

        public new DataHash Value
        {
            get { return _value; }
        }

        public ImprintTag(byte[] bytes) : base(bytes)
        {
            _value = new DataHash(base.Value);
        }

        public ImprintTag(TlvTag tag) : base(tag)
        {
            _value = new DataHash(tag.EncodeValue());
        }

        // TODO: Check null on imprint
        public ImprintTag(uint type, bool nonCritical, bool forward, DataHash value)
            : base(type, nonCritical, forward, value.Imprint)
        {
            _value = value;
        }

        public override byte[] EncodeValue()
        {
            return Value.Imprint;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return Value.GetHashCode() + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        public override bool Equals(object obj)
        {
            ImprintTag tag = obj as ImprintTag;
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
