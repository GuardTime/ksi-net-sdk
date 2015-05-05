using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Signature
{
    public class AggregationHashChain : ICompositeTag
    {
        protected IntegerTag aggregationTime;

        protected List<IntegerTag> chainIndex;

        protected RawTag inputData;

        protected ImprintTag inputHash;

        protected IntegerTag aggrAlgorithmId;

        protected List<CompositeTag<Link>> chain;

        // the hash algorithm identified by aggrAlgorithmId
        protected HashAlgorithm aggrAlgorithm;

        public ITlvTag GetMember(ITlvTag tag)
        {

            switch (tag.Type)
            {
                case 0x2:
                    aggregationTime = new IntegerTag(tag);
                    return aggregationTime;
                case 0x3:
                    if (chainIndex == null)
                    {
                        chainIndex = new List<IntegerTag>();
                    }

                    var chainIndexTag = new IntegerTag(tag);
                    chainIndex.Add(chainIndexTag);

                    return chainIndexTag;
                case 0x4:
                    inputData = new RawTag(tag);
                    return inputData;
                case 0x5:
                    inputHash = new ImprintTag(tag);
                    return inputHash;
                case 0x6:
                    aggrAlgorithmId = new IntegerTag(tag);
                    return aggrAlgorithmId;
                case 0x7:
                case 0x8:
                    if (chain == null)
                    {
                        chain = new List<CompositeTag<Link>>();
                    }

                    var linkTag = new CompositeTag<Link>(tag, new Link((LinkDirection)Enum.ToObject(typeof(LinkDirection), (byte)tag.Type)));
                    chain.Add(linkTag);
                    return linkTag;
            }

            return null;
        }

        protected class Link : ICompositeTag
        {

            protected IntegerTag levelCorrection;

            protected ImprintTag siblingHash;

            protected ImprintTag metaHash;

            private CompositeTag<MetaData> metaData;

            private LinkDirection _direction;

            // the client ID extracted from metaHash
            protected String metaHashId;

            public Link(LinkDirection direction)
            {
                _direction = direction;
            }

            public ITlvTag GetMember(ITlvTag tag)
            {
                switch (tag.Type)
                {
                    case 0x1:
                        levelCorrection = new IntegerTag(tag);
                        return levelCorrection;
                    case 0x2:
                        siblingHash = new ImprintTag(tag);
                        return siblingHash;
                    case 0x3:
                        metaHash = new ImprintTag(tag);
                        return metaHash;
                    case 0x4:
                        metaData = new CompositeTag<MetaData>(tag, new MetaData());
                        return metaData;
                }

                return null;
            }
        }

        class MetaData : ICompositeTag
        {

            private StringTag clientId;

            private StringTag machineId;

            private IntegerTag sequenceNr;

            //Please do keep in mind that request time is in milliseconds!
            private IntegerTag requestTime;

            public ITlvTag GetMember(ITlvTag tag)
            {
                switch (tag.Type)
                {
                    case 0x1:
                        clientId = new StringTag(tag);
                        return clientId;
                    case 0x2:
                        machineId = new StringTag(tag);
                        return machineId;
                    case 0x3:
                        sequenceNr = new IntegerTag(tag);
                        return sequenceNr;
                    case 0x4:
                        requestTime = new IntegerTag(tag);
                        return requestTime;
                }

                return null;
            }
        } 

        class ChainResult
        {
            private DataHash lastHash;
            private int level;

        } 
    }
}
