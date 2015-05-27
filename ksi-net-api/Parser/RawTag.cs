
namespace Guardtime.KSI.Parser
{
    public class RawTag : TlvTag
    {
        public new byte[] Value
        {
            get { return base.Value; }
        }

        public RawTag(byte[] bytes) : base(bytes)
        {
        }

        public RawTag(TlvTag tag) : base(tag)
        {
        }

        public RawTag(uint type, bool nonCritical, bool forward, byte[] data)
            : base(type, nonCritical, forward, data)
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
                int res = 1;
                for (int i = 0; i < Value.Length; i++)
                {
                    res = 31 * res + Value[i];
                }

                return res + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
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
