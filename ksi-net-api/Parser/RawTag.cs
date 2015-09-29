using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     Octet String TLV element.
    /// </summary>
    public class RawTag : TlvTag, IEquatable<RawTag>
    {
        private readonly byte[] _value;

        // TODO: Test with encode returning null
        /// <summary>
        ///     Create new octet string TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV tag is null or encodeValue returns null</exception>
        public RawTag(TlvTag tag) : base(tag)
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
            _value = value;
        }

        /// <summary>
        ///     Get TLV element byte array value.
        /// </summary>
        public byte[] Value
        {
            get { return _value; }
        }

        /// <summary>
        ///     Compare TLV element against raw TLV element.
        /// </summary>
        /// <param name="tag">Raw TLV element</param>
        /// <returns>true if elements are equal</returns>
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

        /// <summary>
        ///     Return TLV element byte array value.
        /// </summary>
        /// <returns>TLV element value</returns>
        public override byte[] EncodeValue()
        {
            return _value;
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
                for (int i = 0; i < _value.Length; i++)
                {
                    res = 31*res + _value[i];
                }

                return res + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        /// <summary>
        ///     Compare TLV element to object.
        /// </summary>
        /// <param name="obj">Comparable object.</param>
        /// <returns>Is given object equal</returns>
        public override bool Equals(object obj)
        {
            return Equals(obj as RawTag);
        }

        /// <summary>
        ///     Compare raw TLV elements against each other.
        /// </summary>
        /// <param name="a">Raw TLV element</param>
        /// <param name="b">Raw TLV element</param>
        /// <returns>true if elements are equal</returns>
        public static bool operator ==(RawTag a, RawTag b)
        {
            return ReferenceEquals(a, null) ? ReferenceEquals(b, null) : a.Equals(b);
        }

        /// <summary>
        ///     Compare raw TLV elements non equity.
        /// </summary>
        /// <param name="a">Raw TLV element</param>
        /// <param name="b">Raw TLV element</param>
        /// <returns>true if elements are not equal</returns>
        public static bool operator !=(RawTag a, RawTag b)
        {
            return !(a == b);
        }
    }
}