namespace Guardtime.KSI.Exceptions
{
    class InvalidTlvStructureException : KsiException
    {
        public InvalidTlvStructureException(string message) : base(message)
        {
        }

        public InvalidTlvStructureException(string message, System.Exception innerException) : base(message, innerException)
        {
        }
    }
}
