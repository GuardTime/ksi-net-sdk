namespace Guardtime.KSI.Service
{
    public interface IKsiService
    {
        void CreateSignature();
        void ExtendSignature();
        void ExtendSignature(byte[] data);
        void GetPublicationsFile();
    }
}