using System;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using System.Collections.Generic;

namespace Guardtime.KSI.Signature
{
    public class AggregationHashChain : CompositeTag
    {
        protected IntegerTag AggregationTime;

        protected List<IntegerTag> ChainIndex;

        protected RawTag InputData;

        protected ImprintTag InputHash;

        protected IntegerTag AggrAlgorithmId;

        protected List<Link> Chain;

        // the hash algorithm identified by aggrAlgorithmId
        protected HashAlgorithm AggrAlgorithm;

        public AggregationHashChain(ITlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                        Value[i] = AggregationTime = new IntegerTag(Value[i]);
                        break;
                    case 0x3:
                        if (ChainIndex == null)
                        {
                            ChainIndex = new List<IntegerTag>();
                        }

                        var chainIndexTag = new IntegerTag(Value[i]);
                        ChainIndex.Add(chainIndexTag);
                        Value[i] = chainIndexTag;
                        break;
                    case 0x4:
                        Value[i] = InputData = new RawTag(Value[i]);
                        break;
                    case 0x5:
                        Value[i] = InputHash = new ImprintTag(Value[i]);
                        break;
                    case 0x6:
                        Value[i] = AggrAlgorithmId = new IntegerTag(Value[i]);
                        break;
                    case 0x7:
                    case 0x8:
                        if (Chain == null)
                        {
                            Chain = new List<Link>();
                        }

                        var linkTag = new Link(Value[i], (LinkDirection)Enum.ToObject(typeof(LinkDirection), (byte)Value[i].Type));
                        Chain.Add(linkTag);
                        Value[i] = linkTag;
                        break;
                }
            }
        }

        protected class Link : CompositeTag
        {

            protected IntegerTag LevelCorrection;

            protected ImprintTag SiblingHash;

            protected ImprintTag MetaHash;

            private MetaData _metaData;

            private LinkDirection _direction;

            // the client ID extracted from metaHash
            protected string metaHashId;


            public Link(ITlvTag tag, LinkDirection direction) : base(tag)
            {
                for (var i = 0; i < Value.Count; i++)
                {
                    switch (Value[i].Type)
                    {
                        case 0x1:
                            Value[i] = LevelCorrection = new IntegerTag(Value[i]);
                            break;
                        case 0x2:
                            Value[i] = SiblingHash = new ImprintTag(Value[i]);
                            break;
                        case 0x3:
                            Value[i] = MetaHash = new ImprintTag(Value[i]);
                            break;
                        case 0x4:
                            Value[i] = _metaData = new MetaData(Value[i]);
                            break;
                    }
                }
            }
            
        }

        class MetaData : CompositeTag
        {

            private StringTag _clientId;

            private StringTag _machineId;

            private IntegerTag _sequenceNr;

            //Please do keep in mind that request time is in milliseconds!
            private IntegerTag _requestTime;

            public MetaData(ITlvTag tag) : base(tag)
            {
                for (var i = 0; i < Value.Count; i++)
                {
                    switch (Value[i].Type)
                    {
                        case 0x1:
                            Value[i] = _clientId = new StringTag(Value[i]);
                            break;
                        case 0x2:
                            Value[i] = _machineId = new StringTag(Value[i]);
                            break;
                        case 0x3:
                            Value[i] = _sequenceNr = new IntegerTag(Value[i]);
                            break;
                        case 0x4:
                            Value[i] = _requestTime = new IntegerTag(Value[i]);
                            break;
                    }
                }
            }
            
        } 

        class ChainResult
        {
            private DataHash lastHash;
            private int level;

        }


        
    }
}
