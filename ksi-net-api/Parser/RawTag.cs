
using Guardtime.KSI.Utils;
using System;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Octet String TLV element.
    /// </summary>
    public class RawTag : TlvTag
    {
        private readonly byte[] _value;

        /// <summary>
        /// Get TLV element byte array value.
        /// </summary>
        public byte[] Value
        {
            get { return _value; }
        }

        // TODO: Test with encode returning null
        /// <summary>
        /// Create new octet string TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public RawTag(TlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                // TODO: Check exception message
                throw new ArgumentException("Invalid TLV element encoded value: null");
            }
            _value = data;
        }

        /// <summary>
        /// Create new octet string TLV element from data
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
                throw new ArgumentNullException("value");
            }
            _value = value;
        }

        /// <summary>
        /// Return TLV element byte array value.
        /// </summary>
        /// <returns>TLV element value</returns>
        public override byte[] EncodeValue()
        {
            return _value;
        }

        /// <summary>
        /// Get TLV element hash code.
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                int res = 1;
                for (int i = 0; i < _value.Length; i++)
                {
                    res = 31 * res + _value[i];
                }

                return res + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        /// <summary>
        /// Compare TLV element to object.
        /// </summary>
        /// <param name="obj">Comparable object</param>
        /// <returns>Is TLV element equal to object</returns>
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
                   Util.IsArrayEqual(tag.EncodeValue(), EncodeValue());
        }
    }

}
