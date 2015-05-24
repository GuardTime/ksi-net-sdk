using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public abstract class CompositeTag : TlvTag
    {
        // TODO: Make list thread safe
        public new List<TlvTag> Value;
        // TODO: Create possibility to check composite tag validity

        protected CompositeTag(byte[] bytes) : this(null, bytes)
        {
        }

        protected CompositeTag(TlvTag parent, byte[] bytes) : base(parent, bytes)
        {
            Value = new List<TlvTag>();
            DecodeValue(base.Value);
        }

        protected CompositeTag(TlvTag tag) : this(null, tag)
        {
        }

        protected CompositeTag(TlvTag parent, TlvTag tag) : base(parent, tag)
        {
            Value = new List<TlvTag>();
            DecodeValue(tag.EncodeValue());
        }

        protected CompositeTag(uint type, bool nonCritical, bool forward)
            : this(null, type, nonCritical, forward)
        {
        }

        protected CompositeTag(TlvTag parent, uint type, bool nonCritical, bool forward)
            : base(parent, type, nonCritical, forward, new byte[] {})
        {
            Value = new List<TlvTag>();
        }

        

        public T PutTag<T>(T tag, TlvTag previousTag) where T : TlvTag
        {
            if (ReplaceTag(tag, previousTag) == null && tag != null)
            {
                AddTag(tag);
            }

            return tag;
        }

        public T AddTag<T>(T tag) where T : TlvTag
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            Value.Add(tag);
            return tag;
        }

        public T ReplaceTag<T>(T tag, TlvTag previousTag) where T : TlvTag
        {
            if (previousTag == null)
            {
                return null;
            }

            int i = Value.IndexOf(previousTag);
            if (i == -1)
            {
                return null;
            }

            Value[i] = tag;
            return tag;
        }

        private void DecodeValue(byte[] bytes)
        {
            
            using (MemoryStream stream = new MemoryStream(bytes))
            using (TlvReader tlvReader = new TlvReader(stream))
            {
                while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                {
                    Value.Add(tlvReader.ReadTag(this));
                }
            }
        }

        public override byte[] EncodeValue()
        {
            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                for (int i = 0; i < Value.Count; i++)
                {
                    writer.WriteTag(Value[i]);
                }

                return stream.ToArray();
            }
        }

        public abstract bool IsValidStructure();


        public override int GetHashCode()
        {
            unchecked
            {
                return Value.GetHashCode() + Type.GetHashCode() + Forward.GetHashCode() + NonCritical.GetHashCode();
            }
        }

        public override bool Equals(object obj)
        {
            CompositeTag tag = obj as CompositeTag;
            if (tag == null || (tag.Type != Type && tag.Forward != Forward && tag.NonCritical != NonCritical))
            {
                return false;
            }
            
            IEnumerator<TlvTag> tagEnumerator = tag.Value == null ? (IEnumerator<TlvTag>) new Util.EmptyEnumerator<TlvTag>() : tag.Value.GetEnumerator();
            IEnumerator<TlvTag> enumerator = Value == null ? (IEnumerator<TlvTag>) new Util.EmptyEnumerator<TlvTag>() : Value.GetEnumerator();
            bool match = true;
            while (match && tagEnumerator.MoveNext() && enumerator.MoveNext())
            {
                TlvTag value1 = tagEnumerator.Current;
                TlvTag value2 = enumerator.Current;
                match = value1 == null ? value2 == null : value1.Equals(value2);
            }

            return match;
        }

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

            builder.Append("]:").Append('\n');

            for (int i = 0; i < Value.Count; i++)
            {
                builder.Append(TabPrefix(Value[i].ToString()));
                builder.Append("\n");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        protected string TabPrefix(string s)
        {
            StringBuilder builder = new StringBuilder();

            string[] lines = s.Split('\n');
            for (int i = 0; i < lines.Length; i++)
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
