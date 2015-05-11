using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parse
{
    public class CompositeContent : ITlvContent
    {

        public List<TlvElement> Value;

        public CompositeContent(byte[] bytes)
        {
            Value = new List<TlvElement>();
            using (var tlvReader = new TlvReader(new MemoryStream(bytes)))
            {
                while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                {
                    Value.Add(tlvReader.ReadTag());
                }
            }
        }

        public byte[] EncodeValue()
        {
            throw new NotImplementedException();
        }

        public sealed override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append('\n');

            for (var i = 0; i < Value.Count; i++)
            {
                builder.Append(TabPrefix(Value[i].ToString()));
                builder.Append("\n");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        protected string TabPrefix(string s)
        {
            var builder = new StringBuilder();

            var lines = s.Split('\n');
            for (var i = 0; i < lines.Length; i++)
            {
                builder.Append("  ");
                builder.Append(lines[i]);
                if (!lines[i].Equals(lines[lines.Length - 1]))
                {
                    builder.Append("\n");
                }
            }

            return builder.ToString();
        }
    }
}
