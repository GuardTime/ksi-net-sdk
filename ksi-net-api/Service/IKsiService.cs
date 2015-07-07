
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using System;

namespace Guardtime.KSI.Service
{
    public interface IKsiService
    {
        KsiSignature CreateSignature(DataHash hash);
        IAsyncResult BeginCreateSignature(DataHash hash, AsyncCallback callback, object asyncState);
        KsiSignature EndCreateSignature(IAsyncResult asyncResult);
        KsiSignature ExtendSignature(KsiSignature signature);
        KsiSignature ExtendSignature(KsiSignature signature, PublicationRecord publicationRecord);
        IAsyncResult BeginExtendSignature(KsiSignature signature, AsyncCallback callback, object asyncState);
        IAsyncResult BeginExtendSignature(KsiSignature signature, PublicationRecord publicationRecord, AsyncCallback callback, object asyncState);
        KsiSignature EndExtendSignature(IAsyncResult asyncResult);
        PublicationsFile GetPublicationsFile();
        IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState);
        PublicationsFile EndGetPublicationsFile(IAsyncResult asyncResult);
    }
}
