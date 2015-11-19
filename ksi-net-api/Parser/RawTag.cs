using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     Octet String TLV element.
    /// </summary>
    public class RawTag : TlvTag
    {
        /// <summary>
        ///     Create new octet string TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public RawTag(ITlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                throw new TlvException("Invalid TLV element encoded value: null.");
            }
            Value = data;
        }

        /// <summary>
        ///     Create new octet string TLV element from data
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element byte array value</param>
        public RawTag(uint type, bool nonCritical, bool forward, byte[] value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new TlvException("Invalid input value: null.");
            }
            Value = value;
        }

        /// <summary>
        ///     Get TLV element byte array value.
        /// </summary>
        public byte[] Value { get; }

        /// <summary>
        ///     Return TLV element byte array value.
        /// </summary>
        /// <returns>TLV element value</returns>
        public override byte[] EncodeValue()
        {
            return Value;
        }

        /// <summary>
        ///     Get TLV element hash code.
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                int res = 1;
                foreach (byte value in Value)
                {
                    res = 31 * res + value;
                }

                return res + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }
    }
}