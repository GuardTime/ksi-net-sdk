using Guardtime.KSI.Utils;
using System;
using System.Text;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// String TLV element.
    /// </summary>
    public class StringTag : TlvTag, IEquatable<StringTag>
    {
        private readonly string _value;
        /// <summary>
        /// Get TLV element string value.
        /// </summary>
        public string Value
        {
            get { return _value; }
        }

        /// <summary>
        /// Create string TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        public StringTag(TlvTag tag) : base(tag)
        {
            byte[] data = tag.EncodeValue();
            if (data == null)
            {
                // TODO: Check exception message
                throw new ArgumentException("Invalid TLV element encoded value: null", "tag");
            }
            _value = Util.DecodeNullTerminatedUtf8String(data);
        }

        /// <summary>
        /// Create string TLV element from data.
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        /// <param name="value">TLV element string value</param>
        public StringTag(uint type, bool nonCritical, bool forward, string value)
            : base(type, nonCritical, forward)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }
            _value = value;
        }

        /// <summary>
        /// Encode element value string to byte array.
        /// </summary>
        /// <returns>string as byte array</returns>
        public override byte[] EncodeValue()
        {
            return Util.EncodeNullTerminatedUtf8String(Value);
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
                for (int i = 0; i < Value.Length; i++)
                {
                    res = 31 * res + Value[i];
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
            return Equals(obj as StringTag);
        }

        /// <summary>
        /// Compare TLV element against string TLV element.
        /// </summary>
        /// <param name="tag">String TLV element</param>
        /// <returns>true if elements are equal</returns>
        public bool Equals(StringTag tag)
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

            return  Type == tag.Type &&
                    Forward == tag.Forward &&
                    NonCritical == tag.NonCritical &&
                    Value == tag.Value;
        }

        /// <summary>
        /// Convert TLV element to string.
        /// </summary>
        /// <returns>TLV element as string</returns>
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("TLV[0x").Append(Type.ToString("X"));

            if (NonCritical)
            {
                builder.Append(",N");
            }

            if (Forward)
            {
                builder.Append(",F");
            }

            builder.Append("]:");
            builder.Append("\"").Append(Value).Append("\"");
            return builder.ToString();
        }

        /// <summary>
        /// Compare string TLV elements against each other.
        /// </summary>
        /// <param name="a">String TLV element</param>
        /// <param name="b">String TLV element</param>
        /// <returns>true if elements are equal</returns>
        public static bool operator ==(StringTag a, StringTag b)
        {
            return ReferenceEquals(a, null) ? ReferenceEquals(b, null) : a.Equals(b);
        }

        /// <summary>
        /// Compare string TLV elements non equity.
        /// </summary>
        /// <param name="a">String TLV element</param>
        /// <param name="b">String TLV element</param>
        /// <returns>true if elements are not equal</returns>
        public static bool operator !=(StringTag a, StringTag b)
        {
            return !(a == b);
        }

    }

}
