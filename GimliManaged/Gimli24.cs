using System;
using System.Numerics;
#if DEBUG
using System.Diagnostics;
#endif

namespace GimliManaged
{
    public class Gimli24
    {
        /// <summary>
        /// Internal state of Gimli (and permute/absorb methods) for v1 as proposed to NIST.
        /// Uses 24 rounds during <see cref="Statev1.Permute"/>
        /// </summary>
        public class Statev1
        {
            private static readonly UInt32 R_CONST = 0x9e377900;
            /// <summary>
            /// The number of bytes in the Rate portion of the Gimli state.
            /// </summary>
            public static readonly Int32 RATE_BYTES = 16;
            private UInt32[] s = new uint[12];  // 384 bits of state stored as 3x4 UInts (48 bytes)         

            /// <summary>
            /// Construst a new <see cref="Statev1"/> object. 
            /// Initializes a "Zero" state with no parameters.
            /// Optionally supply <paramref name="Nonce"/> AND <paramref name="Key"/> for Encryption/Decryption processes.
            /// </summary>
            /// <param name="Nonce"></param>
            /// <param name="Key"></param>
            public Statev1(byte[] Nonce = null, byte[] Key = null)
            {
                if ((Nonce != null && Key == null) ||
                    (Nonce == null && Key != null))
                    throw new InvalidOperationException(
                        "Cannot create a new Statev1 without complete information. Either specify both a Key and Nonce, or neither (creates a zero state).");
                else if (Nonce != null && Key != null)
                {
                    if (Nonce.Length != 16 || Key.Length != 32)
                        throw new ArgumentOutOfRangeException(null, "If using the Nonce and Key, Nonce must be 16 bytes, and Key must be 32 bytes");
                }
                if (Nonce == null || Key == null) return;
                Buffer.BlockCopy(Nonce, 0, s, 0, 16); // s0 = nonce
                Buffer.BlockCopy(Key, 0, s, 16, 16); // s1 = key first half
                Buffer.BlockCopy(Key, 16, s, 32, 16); // s2 = key second half
                Permute();
            }
            private void SmallSwap()
            {
                //s0,0, s0,1, s0,2, s0,3 ← s0,1, s0,0, s0,3, s0,2
                // https://en.wikipedia.org/wiki/XOR_swap_algorithm
                s[0] ^= s[1]; // left two ints
                s[1] ^= s[0];
                s[0] ^= s[1];
                s[2] ^= s[3]; // right two ints
                s[3] ^= s[2];
                s[2] ^= s[3];
            }
            private void BigSwap()
            {
                //s0,0, s0,1, s0,2, s0,3 ← s0,2, s0,3, s0,0, s0,1
                s[0] ^= s[2]; // first and third ints
                s[2] ^= s[0];
                s[0] ^= s[2];
                s[1] ^= s[3]; // second and fouth ints
                s[3] ^= s[1];
                s[1] ^= s[3];
            }
            /// <summary>
            /// Perform the Gimli operation
            /// </summary>
            public void Permute()
            {
                UInt32 x, y, z;
                for (UInt32 r = 24; r > 0; r--)
                {
                    for (byte j = 0; j < 4; j++) // sp box
                    {
                        x = BitOperations.RotateLeft(s[j], 24);
                        y = BitOperations.RotateLeft(s[j + 4], 9);
                        z = s[j + 8];
                        s[j + 8] = x ^ (z << 1) ^ ((y & z) << 2);
                        s[j + 4] = y ^ x        ^ ((x | z) << 1);
                        s[j]     = z ^ y        ^ ((x & y) << 3);
                    }
                    // linear layer
                    if (r % 4 == 0) // every 4th round
                        SmallSwap();    // s...s...s...s... etc.
                    if (r % 4 == 2) // every 4th round starting at the 3rd
                        BigSwap();      // ..S...S...S...S...etc.
                    if (r % 4 == 0) // xor constant + round num, every 4th round
                        s[0] ^= R_CONST ^ (r);    // c...c...c...c... etc.
                }
            }
            /// <summary>
            /// Extract the Rate portion of the State as a byte array length <see cref="RATE_BYTES"/>
            /// </summary>
            public byte[] Squeeze()
            {
                byte[] result = new byte[RATE_BYTES];
                Squeeze(result);
                return result;
            }
            /// <summary>
            /// Extract the Rate portion of the State into a supplied <paramref name="destination"/> byte array at given <paramref name="offset"/>.
            /// </summary>
            /// <exception cref="System.ArgumentNullException">destination is null</exception>
            /// <exception cref="System.ArgumentOutOfRangeException">offset + <see cref="RATE_BYTES"/> goes past end of destination array</exception>
            public void Squeeze(byte[] destination, int offset = 0)
            {
                if (destination == null)
                    throw new ArgumentNullException("destination");
                if (offset + RATE_BYTES > destination.Length)
                    throw new ArgumentOutOfRangeException("Offset goes past end of destination array.");
                Buffer.BlockCopy(s, 0, destination, offset, RATE_BYTES);
            }
            public void AbsorbBlock(ReadOnlySpan<byte> data) // additional data / hashing
            {
                byte[] stuff = Squeeze(); // get a copy of the RATE portion of the state
                for (int i = 0; i < RATE_BYTES; i++)
                {
                    stuff[i] ^= data[i]; // merge/xor state (copy) with data
                }
                Buffer.BlockCopy(stuff, 0, s, 0, RATE_BYTES); // state is overwritten with merged data
                Permute();
            }
            public void AbsorbLastBlock(ReadOnlySpan<byte> data)
            {
                byte[] stuff = Squeeze(); // get a copy of the RATE portion of the state
                for (int i = 0; i < data.Length % RATE_BYTES; i++)
                {
                    stuff[i] ^= data[i]; // merge/xor state (copy) with data
                }
                stuff[data.Length % RATE_BYTES] ^= 0x01; // the reference C has 0x1f, everything else has 0x01
                Buffer.BlockCopy(stuff, 0, s, 0, RATE_BYTES); // state is overwritten with merged data
                s[11] ^= 0x01000000; // the reference C has 0x80 for the last most byte, everything else has 0x01
                Permute();
            }
            public void MergeBlock(ReadOnlySpan<byte> data, ref Span<byte> destination, int offset) // encryption
            {
                byte[] stuff = Squeeze(); // get a copy of the RATE portion of the state
                for (int i = 0; i < RATE_BYTES; i++)
                {
                    stuff[i] ^= data[i]; // merge/xor state (copy) with data
                    destination[i + offset] = stuff[i]; // data is updated to the new value
                }
                Buffer.BlockCopy(stuff, 0, s, 0, RATE_BYTES); // state is overwritten with merged data
                Permute();
            }
            public void MergeLastBlock(ReadOnlySpan<byte> data, ref Span<byte> destination, int offset)
            {
                byte[] stuff = Squeeze(); // get a copy of the RATE portion of the state
                for (int i = 0; i < data.Length % RATE_BYTES; i++)
                {
                    stuff[i] ^= data[i]; // merge/xor state (copy) with data
                    destination[i + offset] = stuff[i]; // data is updated to the new value
                }
                stuff[data.Length % RATE_BYTES] ^= 1;
                Buffer.BlockCopy(stuff, 0, s, 0, RATE_BYTES); // state is overwritten with merged data
                s[11] ^= 0x01000000;
                Permute();
            }
            public void StripBlock(ReadOnlySpan<byte> data, ref Span<byte> destination, int offset) // decryption
            {
                byte[] stuff = Squeeze(); // get a copy of the RATE portion of the state
                for (int i = 0; i < RATE_BYTES; i++)
                {
                    destination[i + offset] = (byte)(data[i] ^ stuff[i]); // merge/xor state (copy) with data at output
                    stuff[i] = data[i]; // set state to data
                }
                Buffer.BlockCopy(stuff, 0, s, 0, RATE_BYTES); // state is overwritten with data
                Permute();
            }
            public void StripLastBlock(ReadOnlySpan<byte> data, ref Span<byte> destination, int offset)
            {
                byte[] stuff = Squeeze(); // get a copy of the RATE portion of the state
                for (int i = 0; i < data.Length % RATE_BYTES; i++)
                {
                    destination[i + offset] = (byte)(data[i] ^ stuff[i]); // merge/xor state (copy) with data at output
                    stuff[i] = data[i]; // set state to data
                }
                stuff[data.Length % RATE_BYTES] ^= 1;
                Buffer.BlockCopy(stuff, 0, s, 0, RATE_BYTES); // state is overwritten with data
                s[11] ^= 0x01000000;
                Permute();
            }
        }
    }
}
