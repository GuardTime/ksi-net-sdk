using System;

namespace Guardtime.KSI.Service
{
    public interface IKsiServiceProtocol
    {
        IAsyncResult BeginCreateSignature(byte[] data, AsyncCallback callback, object asyncState);
        byte[] EndCreateSignature(IAsyncResult asyncResult);
        IAsyncResult BeginExtendSignature(byte[] data, AsyncCallback callback, object asyncState);
        byte[] EndExtendSignature(IAsyncResult asyncResult);
        IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState);
        byte[] EndGetPublicationsFile(IAsyncResult asyncResult);
    }
}