
using Guardtime.KSI.Utils;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Octet String TLV element.
    /// </summary>
    public class RawTag : TlvTag, IEquatable<RawTag>
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
                throw new ArgumentException("Invalid TLV element encoded value: null", "tag");
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
        /// <param name="obj">Comparable object.</param>
        /// <returns>Is given object equal</returns>
        public override bool Equals(object obj)
        {
            return Equals(obj as RawTag);
        }

        public bool Equals(RawTag tag)
        {
            // If parameter is null, return false. 
            if (ReferenceEquals(tag, null))
            {
                return false;
            }

            if (ReferenceEquals(this, tag))
            {
                return true;
            }

            // If run-time types are not exactly the same, return false. 
            if (GetType() != tag.GetType())
            {
                return false;
            }

            return Type == tag.Type &&
                    Forward == tag.Forward &&
                    NonCritical == tag.NonCritical &&
                    Util.IsArrayEqual(EncodeValue(), tag.EncodeValue());
        }

        public static bool operator ==(RawTag a, RawTag b)
        {
            if (ReferenceEquals(a, null))
            {
                if (ReferenceEquals(b, null))
                {
                    return true;
                }

                return false;
            }

            // Equals handles case of null on right side. 
            return a.Equals(b);
        }

        public static bool operator !=(RawTag a, RawTag b)
        {
            return !(a == b);
        }

    }

}
