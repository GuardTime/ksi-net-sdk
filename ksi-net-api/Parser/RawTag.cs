using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     Octet String TLV element.
    /// </summary>
    public class RawTag : TlvTag
    {

        private readonly byte[] _value;

        /// <summary>
        ///     Create new octet string TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV tag is null or encodeValue returns null</exception>
        public RawTag(ITlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                throw new TlvException("Invalid TLV element encoded value: null.");
            }

            _value = data;
        }

        /// <summary>
        ///     Create new octet string TLV element from data
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element byte array value</param>
        /// <exception cref="TlvException">thrown when value is null</exception>
        public RawTag(uint type, bool nonCritical, bool forward, byte[] value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new TlvException("Invalid input value: null.");
            }

            _value = Util.Clone(value);
        }

        /// <summary>
        ///     Get TLV element byte array value.
        /// </summary>
        public byte[] Value => Util.Clone(_value);

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
                for (int i = 0; i < Value.Length; i++)
                {
                    res = 31 * res + Value[i];
                }

                return res + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }
    }
}