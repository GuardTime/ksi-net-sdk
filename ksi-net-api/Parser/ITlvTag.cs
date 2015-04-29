namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Tlv tag interface.
    /// </summary>
    public interface ITlvTag
    {
        /// <summary>
        /// Gets or sets type of tlv tag.
        /// </summary>
        uint Type { get; set; }
        /// <summary>
        /// Gets or sets tlv to be non critical.
        /// </summary>
        bool NonCritical { get; set; }
        /// <summary>
        /// Gets or sets tlv to be forwarded only.
        /// </summary>
        bool Forward { get; set; }

        /// <summary>
        /// Decode and set the tlv value from binary.
        /// </summary>
        /// <param name="valueBytes">binary data</param>
        void DecodeValue(byte[] valueBytes);
        /// <summary>
        /// Encode the tlv value.
        /// </summary>
        /// <returns>encoded tlv value in binary</returns>
        byte[] EncodeValue();
    }
}
