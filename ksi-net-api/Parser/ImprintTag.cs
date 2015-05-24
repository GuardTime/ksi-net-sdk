using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Parser
{
    public class ImprintTag : TlvTag
    {
        public new DataHash Value;

        public ImprintTag(byte[] bytes) : this(null, bytes)
        {
        }

        public ImprintTag(TlvTag parent, byte[] bytes) : base(parent, bytes)
        {
            Value = new DataHash(base.Value);
        }

        public ImprintTag(TlvTag tag) : this(null, tag)
        {
        }

        public ImprintTag(TlvTag parent, TlvTag tag) : base(parent, tag)
        {
            Value = new DataHash(tag.EncodeValue());
        }

        public ImprintTag(uint type, bool nonCritical, bool forward, DataHash value)
            : this(null, type, nonCritical, forward, value)
        {
        }

        public ImprintTag(TlvTag parent, uint type, bool nonCritical, bool forward, DataHash value)
            : base(parent, type, nonCritical, forward, value.Imprint)
        {
            Value = value;
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
