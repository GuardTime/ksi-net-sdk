using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     Imprint TLV element
    /// </summary>
    public class ImprintTag : TlvTag
    {
        /// <summary>
        ///     Create new imprint TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV tag is null or encodeValue returns null</exception>
        public ImprintTag(ITlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                throw new TlvException("Invalid TLV element encoded value: null.");
            }
            Value = new DataHash(data);
        }

        /// <summary>
        ///     Create new imprint TLV element from data.
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">data hash</param>
        /// <exception cref="TlvException">thrown when value is null</exception>
        public ImprintTag(uint type, bool nonCritical, bool forward, DataHash value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new TlvException("Invalid input value: null.");
            }

            Value = value;
        }

        /// <summary>
        ///     Get TLV element data hash
        /// </summary>
        public DataHash Value { get; }

        /// <summary>
        ///     Encode data hash to byte array.
        /// </summary>
        /// <returns>Data hash as byte array</returns>
        public override byte[] EncodeValue()
        {
            return Value.Imprint;
        }

        /// <summary>
        ///     Get TLV element hash code.
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                return Value.GetHashCode() + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }
    }
}