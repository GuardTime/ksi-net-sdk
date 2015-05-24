
namespace Guardtime.KSI.Parser
{
    public class RawTag : TlvTag
    {
        public new byte[] Value
        {
            get { return base.Value; }
        }

        public RawTag(byte[] bytes) : this(null, bytes)
        {
        }

        public RawTag(TlvTag parent, byte[] bytes) : base(parent, bytes)
        {
        }

        public RawTag(TlvTag tag) : this(null, tag)
        {
        }

        public RawTag(TlvTag parent, TlvTag tag) : base(parent, tag)
        {
        }

        public RawTag(uint type, bool nonCritical, bool forward, byte[] data)
            : this(null, type, nonCritical, forward, data)
        {
        }

        public RawTag(TlvTag parent, uint type, bool nonCritical, bool forward, byte[] data)
            : base(parent, type, nonCritical, forward, data)
        {
        }

        public override byte[] EncodeValue()
        {
            return Value;
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
            TlvTag tag = obj as TlvTag;
            if (tag == null)
            {
                return false;
            }

            return tag.Type == Type &&
                   tag.Forward == Forward &&
                   tag.NonCritical == NonCritical &&
                   Util.Util.IsArrayEqual(tag.EncodeValue(), EncodeValue());
        }
    }

}
