using System;
using System.Collections.Generic;
using System.Text;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    /// Invalid TLV Structure exception
    /// </summary>
    public class InvalidTlvStructureException : KsiException
    {
        /// <summary>
        /// TLV element list
        /// </summary>
        public List<TlvTag> TlvList = new List<TlvTag>();

        /// <summary>
        /// Create new InvalidTlvStructure exception.
        /// </summary>
        /// <param name="message">exception message</param>
        public InvalidTlvStructureException(string message) : base(message)
        {

        }

        /// <summary>
        /// Create new InvalidTlvStructure exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="innerException">inner exception</param>
        public InvalidTlvStructureException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Create new InvalidTlvStructure exception.
        /// </summary>
        /// <param name="message">exception message</param>
        /// <param name="tag">invalid tlv tag</param>
        public InvalidTlvStructureException(string message, TlvTag tag) : this(message)
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            TlvList.Add(tag);
        }

        /// <summary>
        /// Get TLV tag trace as string
        /// </summary>
        /// <returns>tlv trace as string</returns>
        public string GetTlvTagTrace()
        {
            if (TlvList.Count == 0) return "";
            StringBuilder builder = new StringBuilder();
            for (int i = TlvList.Count - 1; i >= 0; i--)
            {
                builder.Append("\n").Append(' ', (TlvList.Count - i - 1) * 2);
                builder.Append("TLV[0x").Append(TlvList[i].Type.ToString("X"));

                if (TlvList[i].NonCritical)
                {
                    builder.Append(",N");
                }

                if (TlvList[i].Forward)
                {
                    builder.Append(",F");
                }

                builder.Append("]:");
            }

            builder.Append("0x").Append(Base16.Encode(TlvList[0].EncodeValue()));

            return builder.ToString();
        }
    }
}
