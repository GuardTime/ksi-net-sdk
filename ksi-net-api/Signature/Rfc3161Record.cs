using Guardtime.KSI.Parser;
using System.Collections.Generic;
using System;

namespace Guardtime.KSI.Signature
{
    public class Rfc3161Record : ICompositeTag
    {
        protected IntegerTag aggregationTime;
        protected List<IntegerTag> chainIndex;
        protected ImprintTag inputHash;

        protected RawTag tstInfoPrefix;
        protected RawTag tstInfoSuffix;
        protected IntegerTag tstInfoAlgorithm;

        protected RawTag signedAttributesPrefix;
        protected RawTag signedAttributesSuffix;
        protected IntegerTag signedAttributesAlgorithm;

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

                    var classTag = new IntegerTag(tag);
                    chainIndex.Add(classTag);
                    return classTag;
                case 0x5:
                    inputHash = new ImprintTag(tag);
                    return inputHash;
                case 0x10:
                    tstInfoPrefix = new RawTag(tag);
                    return tstInfoPrefix;
                case 0x11:
                    tstInfoSuffix = new RawTag(tag);
                    return tstInfoSuffix;
                case 0x12:
                    tstInfoAlgorithm = new IntegerTag(tag);
                    return tstInfoAlgorithm;
                case 0x13:
                    signedAttributesPrefix = new RawTag(tag);
                    return signedAttributesPrefix;
                case 0x14:
                    signedAttributesSuffix = new RawTag(tag);
                    return signedAttributesSuffix;
                case 0x15:
                    signedAttributesAlgorithm = new IntegerTag(tag);
                    return signedAttributesAlgorithm;
            }

            return null;

        }
    }
}