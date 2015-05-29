
using System;

namespace Guardtime.KSI.Parser
{
    public class RawTag : TlvTag
    {
        private readonly byte[] _value;
        public byte[] Value
        {
            get { return _value; }
        }

        // TODO: Test with encode returning null
        public RawTag(TlvTag tag) : base(tag)
        {
            _value = tag.EncodeValue();
        }

        public RawTag(uint type, bool nonCritical, bool forward, byte[] value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }
            _value = value;
        }

        public override byte[] EncodeValue()
        {
            return _value;
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
