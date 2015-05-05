
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class CompositeTag<T> : TlvTag<List<ITlvTag>> where T : ICompositeTag
    {

        public T ObjectTag {
            get;
        }

        public CompositeTag(ITlvTag tag, T objectTag) : base(tag)
        {
            // TODO: Correct exception
            if (objectTag == null)
            {
                throw new Exception("Invalid composite object: null");
            }
            ObjectTag = objectTag;
            DecodeValue(tag.EncodeValue());
        }

        public sealed override void DecodeValue(byte[] valueBytes)
        {
            Value = new List<ITlvTag>();
            using (var tlvReader = new TlvReader(new MemoryStream(valueBytes)))
            {
                while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                {
                    var tag = tlvReader.ReadTag();

                    var resultMember = ObjectTag.GetMember(tag);
                    if (resultMember == null)
                    {
                        if (!tag.NonCritical)
                        {
                            // TODO: Create correct handling
                            throw new Exception("BROKEN STRUCTURE [" + tag.Type + "] in " + ObjectTag);
                        }

                        resultMember = tag;
                    }

                    Value.Add(resultMember);
                }
            }
        }

        public sealed override byte[] EncodeValue()
        {
            byte[] output;
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                foreach (var tag in Value)
                {
                    writer.WriteTag(tag);
                }

                output = ((MemoryStream)writer.BaseStream).ToArray();
            }

            return output;
        }

        public sealed override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append(base.ToString()).Append('\n');

            foreach (var tag in Value)
            {
                builder.Append(TabPrefix(tag.ToString()));
                builder.Append("\n");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        protected string TabPrefix(string s) {
            var builder = new StringBuilder();
            
            var lines = s.Split('\n');
            foreach (var str in lines)
            {
                builder.Append("  ");
                builder.Append(str);
                if (!str.Equals(lines[lines.Length - 1])) {
                    builder.Append("\n");
                }
            }

            return builder.ToString();
        }
    }

}
