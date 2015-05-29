using System;
using System.Collections.Generic;
using System.Text;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Exceptions
{
    public class InvalidTlvStructureException : KsiException
    {
        public List<TlvTag> TlvList = new List<TlvTag>();

        public InvalidTlvStructureException(string message) : base(message)
        {

        }

        public InvalidTlvStructureException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public InvalidTlvStructureException(string message, TlvTag tag) : this(message)
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            TlvList.Add(tag);
        }

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

            builder.Append("0x").Append(Util.Util.ConvertByteArrayToString(TlvList[0].EncodeValue()));

            return builder.ToString();
        }
    }
}
