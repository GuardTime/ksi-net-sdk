using System;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Imprint TLV element
    /// </summary>
    public class ImprintTag : TlvTag
    {
        private readonly DataHash _value;

        /// <summary>
        /// Get TLV element data hash
        /// </summary>
        public DataHash Value
        {
            get { return _value; }
        }

        /// <summary>
        /// Create new imprint TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public ImprintTag(TlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                // TODO: Check exception message
                throw new ArgumentException("Invalid TLV element encoded value: null", "tag");
            }
            _value = new DataHash(data);
        }

        // TODO: Check null on imprint
        /// <summary>
        /// Create new imprint TLV element from data.
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">data hash</param>
        public ImprintTag(uint type, bool nonCritical, bool forward, DataHash value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }
            _value = value;
        }

        /// <summary>
        /// Encode data hash to byte array.
        /// </summary>
        /// <returns>Data hash as byte array</returns>
        public override byte[] EncodeValue()
        {
            return _value.Imprint;
        }

        /// <summary>
        /// Get TLV element hash code.
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                return Value.GetHashCode() + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        /// <summary>
        /// Compare TLV element to object.
        /// </summary>
        /// <param name="obj">Comparable object</param>
        /// <returns>Is given object equal</returns>
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

        /// <summary>
        /// Cast TLV element to DataHash
        /// </summary>
        /// <param name="tag">Imprint TLV element</param>
        public static implicit operator DataHash(ImprintTag tag)
        {
            return tag.Value;
        }

    }

}
