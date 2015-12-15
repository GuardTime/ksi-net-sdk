namespace Guardtime.KSI.Hashing
{
    public interface IHmacHasher
    {
        DataHash GetHash(byte[] key, byte[] data);
    }
}