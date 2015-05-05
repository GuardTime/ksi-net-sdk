using System;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Signature
{
    public class SignatureData : ICompositeTag
    {
        protected StringTag signatureType;

        protected RawTag signatureValue;

        protected RawTag certificateId;

        protected StringTag certificateRepositoryUri;

        public ITlvTag GetMember(ITlvTag tag)
        {
            switch (tag.Type)
            {
                case 0x1:
                    signatureType = new StringTag(tag);
                    return signatureType;
                case 0x2:
                    signatureValue = new RawTag(tag);
                    return signatureValue;
                case 0x3:
                    certificateId = new RawTag(tag);
                    return certificateId;
                case 0x4:
                    certificateRepositoryUri = new StringTag(tag);
                    return certificateRepositoryUri;
            }

            return null;
        }
    }
}