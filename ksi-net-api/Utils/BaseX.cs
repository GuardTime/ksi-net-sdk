using System;
using System.Text;

namespace Guardtime.KSI.Utils
{
    /// <summary>
    ///     A generic implementation base for the <a target="_blank" href="http://www.ietf.org/rfc/rfc4648.txt">RFC 4648</a>
    ///     base-X encoders/decoders.
    /// </summary>
    public class BaseX
    {
        /// <summary>
        ///     The number of data bits encoded per character.
        /// </summary>
        private readonly int _bits;

        /// <summary>
        ///     The number of characters in a full block in the encoded form.
        /// </summary>
        private readonly int _block;

        /// <summary>
        ///     A lookup table from values to characters.
        /// </summary>
        private readonly char[] _chars;

        /// <summary>
        ///     The character used for padding the last block when encoding.
        /// </summary>
        private readonly char _pad;

        /// <summary>
        ///     A lookup table from character code points to values. A value of -1 in the
        ///     table indicates the corresponding character is not used in the encoded
        ///     form. The indices {@code 0..values.length-1} correspond to code points
        ///     {@code min..max}.
        /// </summary>
        private readonly int[] _values;

        /// <summary>
        ///     The highest code point used in the encoded form.
        /// </summary>
        private int _max;

        /// <summary>
        ///     The lowest code point used in the encoded form.
        /// </summary>
        private int _min;

        /// <summary>
        ///     Create base converting instance.
        /// </summary>
        /// <param name="alphabet">base alphabet</param>
        /// <param name="caseSensitive">is base conversion case sensitive</param>
        /// <param name="padding">padding</param>
        /// <exception cref="ArgumentException">thrown when alphabet or padding does not match</exception>
        public BaseX(string alphabet, bool caseSensitive, char padding)
        {
            // the bit and byte counts
            _bits = 1;
            while ((1 << _bits) < alphabet.Length)
            {
                _bits++;
            }
            if ((1 << _bits) != alphabet.Length)
            {
                throw new ArgumentException("The size of the encoding alphabet is not a power of 2", "alphabet");
            }

            _block = 8 / Util.GCD(8, _bits);

            // the encoding lookup table
            _chars = alphabet.ToCharArray();

            // the decoding lookup table
            _min = -1;
            _max = -1;
            if (caseSensitive)
            {
                AddMinMax(alphabet);
                _values = new int[_max - _min + 1];
                Util.ArrayFill(_values, -1);
                AddChars(alphabet);
            }
            else
            {
                AddMinMax(alphabet.ToUpper());
                AddMinMax(alphabet.ToLower());
                _values = new int[_max - _min + 1];
                Util.ArrayFill(_values, -1);
                AddChars(alphabet.ToUpper());
                AddChars(alphabet.ToLower());
            }

            // the padding
            if (padding >= _min && padding <= _max && _values[padding - _min] != -1)
            {
                throw new ArgumentException("The padding character appears in the encoding alphabet", "padding");
            }

            _pad = padding;
        }

        private void AddMinMax(string chars)
        {
            if (chars == null)
            {
                throw new ArgumentNullException("chars");
            }

            for (int i = 0; i < chars.Length; i++)
            {
                int c = chars[i];
                if (_min == -1 || _min > c)
                {
                    _min = c;
                }
                if (_max == -1 || _max < c)
                {
                    _max = c;
                }
            }
        }

        private void AddChars(string chars)
        {
            if (chars == null)
            {
                throw new ArgumentNullException("chars");
            }

            for (int i = 0; i < chars.Length; i++)
            {
                int c = chars[i] - _min;
                if (_values[c] != -1 && _values[c] != i)
                {
                    throw new ArgumentException("Duplicate characters in the encoding alphapbet", "chars");
                }
                _values[c] = i;
            }
        }

        /// <summary>
        ///     Encode bytes in given base.
        /// </summary>
        /// <param name="bytes">data bytes</param>
        /// <param name="sep">separator</param>
        /// <param name="freq">frequency</param>
        /// <returns>bytes string representation in given base</returns>
        public string Encode(byte[] bytes, string sep, int freq)
        {
            return Encode(bytes, 0, bytes.Length, sep, freq);
        }

        /// <summary>
        ///     Encode bytes in given base.
        /// </summary>
        /// <param name="bytes">data bytes</param>
        /// <param name="off">offset</param>
        /// <param name="len">length</param>
        /// <param name="sep">separator</param>
        /// <param name="freq">frequency</param>
        /// <returns>bytes string representation in given base</returns>
        public string Encode(byte[] bytes, int off, int len, string sep, int freq)
        {
            // sanitize the parameters
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            if (off < 0 || len < 0 || off + len < 0 || off + len > bytes.Length)
            {
                throw new ArgumentOutOfRangeException();
            }

            if (sep == null)
            {
                freq = 0;
            }
            else
            {
                for (int i = 0; i < sep.Length; i++)
                {
                    int c = sep[i];
                    if (c >= _min && c <= _max && _values[c - _min] != -1)
                    {
                        throw new ArgumentException("The separator contains characters from the encoding alphabet");
                    }
                }
            }

            // create the output buffer
            int outLen = (8 * len + _bits - 1) / _bits;
            outLen = (outLen + _block - 1) / _block * _block;
            if (freq > 0)
            {
                if (sep != null)
                {
                    outLen += (outLen - 1) / freq * sep.Length;
                }
            }

            StringBuilder builder = new StringBuilder(outLen);

            // encode
            int outCount = 0; // number of output characters produced
            int inCount = 0; // number of input bytes consumed
            int buf = 0; // buffer of input bits not yet sent to output
            int bufBits = 0; // number of bits in the bit buffer
            int bufMask = (1 << _bits) - 1;
            while (_bits * outCount < 8 * len)
            {
                if (freq > 0 && outCount > 0 && outCount % freq == 0)
                {
                    builder.Append(sep);
                }
                // fetch the next byte(s), padding with zero bits as needed
                while (bufBits < _bits)
                {
                    int next = (inCount < len
                        ? bytes[off + inCount]
                        : 0)
                        ;
                    inCount++;
                    buf = (buf << 8) | (next & 0xff); // we want unsigned bytes
                    bufBits += 8;
                }

                // output the top bits from the bit buffer
                builder.Append(_chars[(buf >> (bufBits - _bits)) & bufMask]);
                bufBits -= _bits;
                outCount++;
            }

            // pad
            while (outCount % _block != 0)
            {
                if (freq > 0 && outCount > 0 && outCount % freq == 0)
                {
                    builder.Append(sep);
                }
                builder.Append(_pad);
                outCount++;
            }

            return builder.ToString();
        }

        /// <summary>
        ///     Decode string base representation.
        /// </summary>
        /// <param name="s">base string</param>
        /// <returns>base decoded byte array</returns>
        public byte[] Decode(string s)
        {
            // sanitize the parameters
            if (s == null)
            {
                throw new ArgumentNullException("s");
            }

            // create the result buffer
            byte[] outputBytes = new byte[s.Length * _bits / 8];

            // decode
            int outCount = 0; // number of output bytes produced
            int inCount = 0; // number of input characters consumed
            int buf = 0; // buffer of input bits not yet sent to output
            int bufBits = 0; // number of bits in the bit buffer
            while (inCount < s.Length)
            {
                int next = s[inCount];

                inCount++;
                if (next < _min || next > _max)
                {
                    continue;
                }
                next = _values[next - _min];
                if (next == -1)
                {
                    continue;
                }
                buf = (buf << _bits) | next;
                bufBits += _bits;
                while (bufBits >= 8)
                {
                    outputBytes[outCount] = (byte)((buf >> (bufBits - 8)) & 0xff);
                    bufBits -= 8;
                    outCount++;
                }
            }

            // trim the result if there were any skipped characters
            if (outCount >= outputBytes.Length)
            {
                return outputBytes;
            }

            return Util.Clone(outputBytes, 0, outCount);
        }
    }
}