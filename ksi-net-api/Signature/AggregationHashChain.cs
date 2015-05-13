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

        protected TlvTag InputData;

        protected ImprintTag InputHash;

        protected IntegerTag AggrAlgorithmId;

        protected List<Link> Chain;

        // the hash algorithm identified by aggrAlgorithmId
        protected HashAlgorithm AggrAlgorithm;

        public AggregationHashChain(TlvTag tag) : base(tag)
        {
            for (var i = 0; i < Value.Count; i++)
            {
                switch (Value[i].Type)
                {
                    case 0x2:
                        AggregationTime = new IntegerTag(Value[i]);
                        Value[i] = AggregationTime;
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
                        InputData = new TlvTag(Value[i]);
                        Value[i] = InputData;
                        break;
                    case 0x5:
                        InputHash = new ImprintTag(Value[i]);
                        Value[i] = InputHash;
                        break;
                    case 0x6:
                        AggrAlgorithmId = new IntegerTag(Value[i]);
                        Value[i] = AggrAlgorithmId;
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


            public Link(TlvTag tag, LinkDirection direction) : base(tag)
            {
                for (var i = 0; i < Value.Count; i++)
                {
                    switch (Value[i].Type)
                    {
                        case 0x1:
                            LevelCorrection = new IntegerTag(Value[i]);
                            Value[i] = LevelCorrection;
                            break;
                        case 0x2:
                            SiblingHash = new ImprintTag(Value[i]);
                            Value[i] = SiblingHash;
                            break;
                        case 0x3:
                            MetaHash = new ImprintTag(Value[i]);
                            Value[i] = MetaHash;
                            break;
                        case 0x4:
                            _metaData = new MetaData(Value[i]);
                            Value[i] = _metaData;
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

            public MetaData(TlvTag tag) : base(tag)
            {
                for (var i = 0; i < Value.Count; i++)
                {
                    switch (Value[i].Type)
                    {
                        case 0x1:
                            _clientId = new StringTag(Value[i]);
                            Value[i] = _clientId;
                            break;
                        case 0x2:
                            _machineId = new StringTag(Value[i]);
                            Value[i] = _machineId;
                            break;
                        case 0x3:
                            _sequenceNr = new IntegerTag(Value[i]);
                            Value[i] = _sequenceNr;
                            break;
                        case 0x4:
                            _requestTime = new IntegerTag(Value[i]);
                            Value[i] = _requestTime;
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
