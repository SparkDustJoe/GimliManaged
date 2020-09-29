using System;
using System.Text;

namespace GimliManaged
{
    public class Gimli24v1
    {
        // hashing first (small), AEAD further down this code file
        public static Int32 TAG_BYTES = 16;
        public static Int32 HASH_LEN = 32;

        /// <summary>
        /// Compute a hash of a byte array using Gimli (as proposed to NIST, v1)
        /// </summary>
        /// <param name="data"></param>
        /// <returns><see cref="HASH_LEN"/> bytes of Hash result</returns>
        public static byte[] ComputeHash(ReadOnlySpan<byte> data)
        {
            Gimli24.Statev1 state = new Gimli24.Statev1(); // zero state
            int d_ptr = 0;
            while (d_ptr + Gimli24.Statev1.RATE_BYTES <= data.Length)
            {
                state.AbsorbBlock(data.Slice(d_ptr, Gimli24.Statev1.RATE_BYTES));
                d_ptr += 16;
            }
            state.AbsorbLastBlock(data.Slice(d_ptr, data.Length % Gimli24.Statev1.RATE_BYTES));
            byte[] result = new byte[32];
            state.Squeeze(result, 0);
            state.Permute();
            state.Squeeze(result, 16);
            return result;
        }

        // encryption

        /// <summary>
        /// Perform AEAD Encryption process on a byte array using a 16-byte <paramref name="Nonce"/> and 32-byte <paramref name="Key"/> using Gimli (as proposed to NIST, v1).
        /// </summary>
        /// <remarks>
        /// Can optionally supply an <paramref name="AdditionalData"/> byte array that will be processed with the <paramref name="Message"/> array.
        /// The Tag/MAC is appended to the output, length <seealso cref="TAG_BYTES"/> (len Ciphertext = len Message + TAG_BYTES).
        /// </remarks>
        /// <param name="Nonce"></param>
        /// <param name="Key"></param>
        /// <param name="AdditionalData"></param>
        /// <param name="Message"></param>
        /// <returns>The encrypted Message + <see cref="TAG_BYTES"/> bytes of Tag/MAC</returns>
        public static byte[] AEADEncrypt(byte[] Nonce, byte[] Key, ReadOnlySpan<byte> AdditionalData, ReadOnlySpan<byte> Message)
        {
            if ((Nonce?.Length ?? 0) != 16)
                throw new ArgumentOutOfRangeException("Nonce", "Nonce must be 16 bytes (and not null).");
            if ((Key?.Length ?? 0) != 32)
                throw new ArgumentOutOfRangeException("Key", "Key must be 32 bytes (and not null).");

            Gimli24.Statev1 state = new Gimli24.Statev1(Nonce, Key);

            int ad_ptr = 0;
            while (ad_ptr + Gimli24.Statev1.RATE_BYTES <= AdditionalData.Length)
            {
                state.AbsorbBlock(AdditionalData.Slice(ad_ptr, Gimli24.Statev1.RATE_BYTES));
                ad_ptr += Gimli24.Statev1.RATE_BYTES;
            }
            state.AbsorbLastBlock(AdditionalData.Slice(ad_ptr, AdditionalData.Length % Gimli24.Statev1.RATE_BYTES));

            byte[] output = new byte[Message.Length + Gimli24.Statev1.RATE_BYTES];
            Span<byte> out_slice = new Span<byte>(output);
            int d_ptr = 0;
            while (d_ptr + Gimli24.Statev1.RATE_BYTES <= Message.Length)
            {
                state.MergeBlock(Message.Slice(d_ptr, Gimli24.Statev1.RATE_BYTES), ref out_slice, d_ptr);
                d_ptr += Gimli24.Statev1.RATE_BYTES;
            }
            state.MergeLastBlock(Message.Slice(d_ptr, Message.Length % Gimli24.Statev1.RATE_BYTES), ref out_slice, d_ptr);

            state.Squeeze(output, output.Length - TAG_BYTES);

            return output;
        }

        /// <summary>
        /// Perform AEAD Decryption process on a byte array using a 16-byte <paramref name="Nonce"/> and 32-byte <paramref name="Key"/> using Gimli (as proposed to NIST, v1).
        /// </summary>
        /// <remarks>
        /// Can optionally supply an <paramref name="AdditionalData"/> byte array that will be processed with the <paramref name="Ciphertext"/> array 
        /// (must be same bytes as was used during <see cref="AEADEncrypt"/>, and should not be null if any AdditionalData was used during encrpytion).
        /// The Tag/MAC (of length <see cref="TAG_BYTES"/>) is expected to be at the end of the input (len Message = len Ciphertext - TAG_BYTES).
        /// </remarks>
        /// <param name="Nonce"></param>
        /// <param name="Key"></param>
        /// <param name="AdditionalData"></param>
        /// <param name="Ciphertext"></param>
        /// <returns>The original Message OR NULL if verification fails.</returns>
        public static byte[] AEADDecryptVerify(byte[] Nonce, byte[] Key, ReadOnlySpan<byte> AdditionalData, ReadOnlySpan<byte> Ciphertext)
        {
            if ((Nonce?.Length ?? 0) != 16)
                throw new ArgumentOutOfRangeException("Nonce", "Nonce must be 16 bytes (and not null).");
            if ((Key?.Length ?? 0) != 32)
                throw new ArgumentOutOfRangeException("Key", "Nonce must be 32 bytes (and not null).");
            if (Ciphertext.Length < 16)
                throw new ArgumentOutOfRangeException("Ciphertext", "Not enough data. Tag might be missing (input len < 16).");

            Gimli24.Statev1 state = new Gimli24.Statev1(Nonce, Key);

            int ad_ptr = 0;
            while (ad_ptr + Gimli24.Statev1.RATE_BYTES <= AdditionalData.Length)
            {
                state.AbsorbBlock(AdditionalData.Slice(ad_ptr, Gimli24.Statev1.RATE_BYTES));
                ad_ptr += Gimli24.Statev1.RATE_BYTES;
            }
            state.AbsorbLastBlock(AdditionalData.Slice(ad_ptr, AdditionalData.Length % Gimli24.Statev1.RATE_BYTES));

            byte[] output = new byte[Ciphertext.Length - TAG_BYTES];
            Span<byte> out_slice = new Span<byte>(output);
            int d_ptr = 0;
            while (d_ptr + Gimli24.Statev1.RATE_BYTES <= output.Length) // last 16 bytes are the tag
            {
                state.StripBlock(Ciphertext.Slice(d_ptr, Gimli24.Statev1.RATE_BYTES), ref out_slice, d_ptr);
                d_ptr += Gimli24.Statev1.RATE_BYTES;
            }
            state.StripLastBlock(Ciphertext.Slice(d_ptr, Ciphertext.Length % Gimli24.Statev1.RATE_BYTES), ref out_slice, d_ptr);

            byte[] tag = state.Squeeze();
            Int32 verify = 0;
            for (byte v = 0; v < TAG_BYTES; v++)
                verify |= tag[v] ^ Ciphertext[Ciphertext.Length - TAG_BYTES + v];
            if (verify == 0)
                return output;
            else
                return null;
        }

        // encryption where Tag is put separate from the ciphertext

        /// <summary>
        /// Perform AEAD Encryption process on a byte array using a 16-byte Nonce, 32-byte Key using Gimli (as proposed to NIST, v1).
        /// </summary>
        /// <remarks>
        /// Can optionally supply an <paramref name="AdditionalData"/> byte array that will be processed with the <paramref name="Message"/> array.
        /// The Tag/MAC is supplied as a separate OUTPUT variable (<paramref name="Tag"/>), length <see cref="TAG_BYTES"/> (len Ciphertext = len Message).
        /// </remarks>
        /// <param name="Nonce"></param>
        /// <param name="Key"></param>
        /// <param name="AdditionalData"></param>
        /// <param name="Message"></param>
        /// <param name="Tag">OUTPUT Tag/MAC of length <see cref="TAG_BYTES"/></param>
        /// <returns>The encrypted Message.</returns>
        public static byte[] AEADEncrypt_Detached(byte[] Nonce, byte[] Key, ReadOnlySpan<byte> AdditionalData, ReadOnlySpan<byte> Message, out byte[] Tag)
        {
            if ((Nonce?.Length ?? 0) != 16)
                throw new ArgumentOutOfRangeException("Nonce", "Nonce must be 16 bytes (and not null).");
            if ((Key?.Length ?? 0) != 32)
                throw new ArgumentOutOfRangeException("Key", "Nonce must be 16 bytes (and not null).");

            Gimli24.Statev1 state = new Gimli24.Statev1(Nonce, Key);

            int ad_ptr = 0;
            while (ad_ptr + Gimli24.Statev1.RATE_BYTES <= AdditionalData.Length)
            {
                state.AbsorbBlock(AdditionalData.Slice(ad_ptr, Gimli24.Statev1.RATE_BYTES));
                ad_ptr += Gimli24.Statev1.RATE_BYTES;
            }
            state.AbsorbLastBlock(AdditionalData.Slice(ad_ptr, AdditionalData.Length % Gimli24.Statev1.RATE_BYTES));

            byte[] output = new byte[Message.Length]; // tag sent separately
            Span<byte> out_slice = new Span<byte>(output);
            int d_ptr = 0;
            while (d_ptr + Gimli24.Statev1.RATE_BYTES <= Message.Length)
            {
                state.MergeBlock(Message.Slice(d_ptr, Gimli24.Statev1.RATE_BYTES), ref out_slice, d_ptr);
                d_ptr += Gimli24.Statev1.RATE_BYTES;
            }
            state.MergeLastBlock(Message.Slice(d_ptr, Message.Length % Gimli24.Statev1.RATE_BYTES), ref out_slice, d_ptr);

            Tag = state.Squeeze();

            return output;
        }

        /// <summary>
        /// Perform AEAD Decryption process on a byte array using a 16-byte <paramref name="Nonce"/> and
        /// 32-byte <paramref name="Key"/> using Gimli (as proposed to NIST, v1), and the <paramref name="Tag"/> output from <see cref="Gimliv1.AEADEncrypt_Detached"/>.
        /// </summary>
        /// <remarks>
        /// Can optionally supply an <paramref name="AdditionalData"/> byte array that will be processed with the <paramref name="Ciphertext"/> array
        /// (must be same bytes as was used during <see cref="Gimliv1.AEADEncrypt_Detached"/>, and should not be null if any AdditionalData was used 
        /// during encrpytion).
        /// </remarks>
        /// <param name="Nonce"></param>
        /// <param name="Key"></param>
        /// <param name="AdditionalData"></param>
        /// <param name="Tag">Tag/MAC of length <see cref="TAG_BYTES"/></param>
        /// <param name="Ciphertext"></param>
        /// <returns>The original Message OR NULL if verification fails.</returns>
        public static byte[] AEADDecryptVerify_Detached(byte[] Nonce, byte[] Key, ReadOnlySpan<byte> AdditionalData, byte[] Tag, ReadOnlySpan<byte> Ciphertext)
        {
            if ((Nonce?.Length ?? 0) != 16)
                throw new ArgumentOutOfRangeException("Nonce", "Nonce must be 16 bytes (and not null).");
            if ((Key?.Length ?? 0) != 32)
                throw new ArgumentOutOfRangeException("Key", "Nonce must be 32 bytes (and not null).");
            if ((Tag?.Length ?? 0) != TAG_BYTES)
                throw new ArgumentOutOfRangeException("Tag", $"Tag must be {TAG_BYTES} bytes (and not null).");

            Gimli24.Statev1 state = new Gimli24.Statev1(Nonce, Key);

            int ad_ptr = 0;
            while (ad_ptr + Gimli24.Statev1.RATE_BYTES <= AdditionalData.Length)
            {
                state.AbsorbBlock(AdditionalData.Slice(ad_ptr, Gimli24.Statev1.RATE_BYTES));
                ad_ptr += Gimli24.Statev1.RATE_BYTES;
            }
            state.AbsorbLastBlock(AdditionalData.Slice(ad_ptr, AdditionalData.Length % Gimli24.Statev1.RATE_BYTES));

            byte[] output = new byte[Ciphertext.Length]; // ciphertext is same length as message, tag is separate
            Span<byte> out_slice = new Span<byte>(output);
            int d_ptr = 0;
            while (d_ptr + Gimli24.Statev1.RATE_BYTES <= output.Length) // last 16 bytes are the tag
            {
                state.StripBlock(Ciphertext.Slice(d_ptr, Gimli24.Statev1.RATE_BYTES), ref out_slice, d_ptr);
                d_ptr += Gimli24.Statev1.RATE_BYTES;
            }
            state.StripLastBlock(Ciphertext.Slice(d_ptr, Ciphertext.Length % Gimli24.Statev1.RATE_BYTES), ref out_slice, d_ptr);

            byte[] local_tag = state.Squeeze();
            Int32 verify = 0;
            for (byte v = 0; v < TAG_BYTES; v++)
                verify |= local_tag[v] ^ Tag[v];
            if (verify == 0)
                return output;
            else
                return null;
        }
    }
}
