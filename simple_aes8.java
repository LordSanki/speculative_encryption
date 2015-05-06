/*
 * 8-bit AES cipher.
 * (C) Peter Breuer 2013 (ptb@inv.it.uc3m.es) for any parts I’ve written
 * myself, the whole of this source having been created by reverse
 * engineering some unattributed fragments of C for larger block AES which I
 * found publicly available on the web via Google with no licence or author
 * named inside (or anywhere around, under, over, etc) those sources.
 * For the record those sources were
 * ecb_decrypt.c 806B
 * ecb_encrypt.c 1089B
 * simple_aes.c 2926B
 * simple_aes_decr.c 3094B
 * and if somebody can recognise and substantiate where those
 * ultimately come from, I’ll be happy to acknowledge as appropriate.
 * The total of comments in those files is
 * ecb_decrypt.c
 * ecb_decrypt.c
 * ecb_decrypt.c
 * ecb_decrypt.c
 * ecb_encrypt.c
 * ecb_encrypt.c
 * I’m happy to place my code here under
 * * Gnu General Public Licence Version 2 (June 1991) *
 * the required rubric for which is
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * To get a copy of the GPL2, search for "GPL", "GPL-2", "GPL2" on the
 * Internet, in particular at fsf.org. Otherwise "write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA" for hardcopy.
 * That licence means, paraphrasing, that you may use this source code
 * and change it and redistribute it in source and/or binary form, but you
 * must acknowledge where it comes from (i.e. include my name in the
 * history) and provide source on demand or by default to whoever you
 * distribute the binary to, and bind recipients of this or derived
 * source to the same or a compatible licence. That means that they are
 * free to change it, have to bind recipients of their binary or source
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * To get a copy of the GPL2, search for "GPL", "GPL-2", "GPL2" on the
 * Internet, in particular at fsf.org. Otherwise "write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA" for hardcopy.
 * That licence means, paraphrasing, that you may use this source code
 * and change it and redistribute it in source and/or binary form, but you
 * must acknowledge where it comes from (i.e. include my name in the
 * history) and provide source on demand or by default to whoever you
 * distribute the binary to, and bind recipients of this or derived
 * source to the same or a compatible licence. That means that they are
 * free to change it, have to bind recipients of their binary or source
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * To get a copy of the GPL2, search for "GPL", "GPL-2", "GPL2" on the
 * Internet, in particular at fsf.org. Otherwise "write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA" for hardcopy.
 * That licence means, paraphrasing, that you may use this source code
 * and change it and redistribute it in source and/or binary form, but you
 * must acknowledge where it comes from (i.e. include my name in the
 * history) and provide source on demand or by default to whoever you
 * distribute the binary to, and bind recipients of this or derived
 * source to the same or a compatible licence. That means that they are
 * free to change it, have to bind recipients of their binary or source
 *
 * simple_aes8(byte) // makes a de/encryption device with
 * byte ecb_encrypt(byte) // encrypt one byte using key
 * byte ecb_decrypt(byte) // decrypt one byte using key
 * setkey(byte) // reset key
 * setverbose() // make debugging noise
 * setquiet() // make no debugging noise
 * 
 */

public class simple_aes8 {
  // 0->3->2->0; 1->1;
  private static int[] sbox = { // permutation used in encryption
    3,1,0,2,
  };
  // 0->2->3->0; 1-1
  private static int[] invsbox = { // inverse permutation
    2,1,3,0
  };

  private byte key;
  private byte[] roundkeys = null; // 8-bit key
  // derived keys
  // derived keys
  private int state;
  private boolean verbose = false; // modified by en/decryption
  private int interstate[] = new int[9];
  private int inverstate[] = new int[9]; // debugging encryption process
  // debugging decryption process
  /*
   * Multiplication in GF(4). Field elements are integers in the range
   * 0...3, which we think of as degree < 2 polynomials over GF(2).
   * a1 a0 * b1 b0 =
   * .. (b1b0+b1b1+b0b1)(a0b0+b1b1)
   * (X**2 = X+1) since X**2+X+1 is irreducible mod 2.
   */
  private static int field_multiply(int a, int b) {
    int ret = 0;
    int[] xmultiples = new int[2]; // a, a*x
    xmultiples[0] = a;
    for (int i = 1; i < 2; i++) // a*x^1 = x*(a*x^0)
      xmultiples[i] = x_multiply(xmultiples[i - 1]);
    for (int i = 0; i < 2; i++) {
      if ((b & 1) != 0)
        ret ^= xmultiples[i]; // b0*a+b1*a*x = b*a
      b >>>= 1;
    }
    return ret;
  }
  /*
   * Multiplication by the element x (= 1*x+0*1 = "10") of the field
   */
  private static int x_multiply(int a) {
    // 4 -> 3, i.e. x**2 -> x+1, so x**2 = x+1
    switch (a) {
      case 0:
        return 0; // x*0 = 0
      case 1:
        // x*1 = x
        return 2;
      case 2:
        return 3; // x*x = x+1
      case 3:
        return 1; // x*(x+1) = x^2+x = 1
    }
    throw new NullPointerException();
  }
  /*
   * Make and install the derived keys from the original key
   */
  void setkey(byte key) {
    if (this.key == key && roundkeys != null)
      return;
    int[] w = new int[6];
    // 4 bits each
    roundkeys = new byte[3];
    w[0] = (key >>> 4) & 0xf;
    // upper 4 bits of key
    w[1] = key & 0xf;
    // lower 4 bits of key
    w[2] = w[0] ^ (2*4)
      // 4 bits
      ^ ((sbox[w[1] & 0x3] << 2) | sbox[w[1] >>> 2]); // 4 bits
    w[3] = w[1] ^ w[2];
    // 4 bits
    w[4] = w[2] ^ (3 * 4)
      // 4 bits
      ^ ((sbox[w[3] & 0x3] << 2) | sbox[w[3] >>> 2]); // 4 bits
    w[5] = w[3] ^ w[4];
    // 4 bits
    roundkeys[0] = (byte)(key & 0xff);
    roundkeys[1] = (byte)((w[2] << 4) | w[3]);
    roundkeys[2] = (byte)((w[4] << 4) | w[5]);
    // 8 bits
    // 8 bits
    // 8 bits
    // those roundkeys seem to have independent 4 bit components
    pdebug("round keys: %04o\t%04o\t%04o\n",
        roundkeys[0], roundkeys[1], roundkeys[2]);
    this.key = key;
  }
  /*
   * Apply a subsitution in each of 4 groups of 2 bits each ("nibbles")
   * to the state.
   */
  private void substitute_nibble() {
    // apply sbox permutation to each nibble
    int[] state_vector = new int[4]; // each is 2 bit!
    int newstate = 0;
    for (int i = 0; i < 4; i++) {
      state_vector[i] = sbox[state & 0x3]; // 2 bit
      state >>>= 2;
    }
    for (int i = 3; i >= 0; i--)
      newstate = (newstate << 2) | state_vector[i];
    state = newstate;
  }
  /*
   * Apply inverse subsitution in each of 4 groups of 2 bits each ("nibbles")
   * to the state.
   */
  private void inv_substitute_nibble() {
    // apply inverse sbox permutation to each nibble
    int[] state_vector = new int[4];
    int newstate = 0;
    for (int i = 0; i < 4; i++) {
      state_vector[i] = invsbox[state & 0x3]; // 2 bit
      state >>= 2;
    }
    for (int i = 3; i >= 0; i--)
      newstate = (newstate << 2) | state_vector[i];
    state = newstate;
  }
  /*
   * Permute the nibbles. (x0,x1,x2,x3) -> (x2,x3,x0,x3)
   * to the state.
   */
  private void swaprow() {
    int[] state_vector = new int[4];
    int newstate = 0;
    for (int i = 0; i < 4; i++) {
      state_vector[i] = state & 0x3;
      state >>= 2;
    }
    // swaps 0<->2 groups of 2 bits
    // 1 0 0 0
    // 0 0 0 1
    // 0 0 1 0
    // 0 1 0 0
    newstate
      = (state_vector[3] << 6)
      | (state_vector[0] << 4)
      | (state_vector[1] << 2)
      | (state_vector[2] << 0);
    state = newstate;
  }
  /*
   * Apply a linear transform to the state as a vector of 4 nibbles
   */
  private void mixcolumns() {
    int[] state_vector = new int[4]; // 2 bits each
    int newstate = 0;
    int oldstate = state;
    int[] newstate_vector = new int[4];
    for (int i = 0; i < 4; i++) {
      state_vector[i] = state & 0x3; // 2 bits
      state >>>= 2;
    }
    // matrix multiplication on groups of 2 bits
    // 1 2 0 0
    // 2 1 0 0
    // 0 0 1 2
    // 0 0 2 1
    newstate_vector[3] = state_vector[3]
      ^ field_multiply(state_vector[2],2);
    newstate_vector[2] = state_vector[2]
      ^ field_multiply(state_vector[3],2);
    newstate_vector[1] = state_vector[1]
      ^ field_multiply(state_vector[0],2);
    newstate_vector[0] = state_vector[0]
      ^ field_multiply(state_vector[1],2);

    for (int i = 3; i >= 0; i--)
      newstate = (newstate << 2) | newstate_vector[i];
    state = newstate;
  }
  /*
   * Apply inverse linear transform to the state as a vector of 4 nibbles
   */
  private void inv_mixcolumns() {
    int[] state_vector = new int[4];
    int
      newstate = 0;
    int[] newstate_vector = new int[4];
    for (int i = 0; i < 4 ; i++) {
      state_vector[i] = state & 0x3;
      state >>>= 2;
    }
    // matrix multiplication on groups of 2 bits
    // 3 1 0 0
    // 1 3 0 0
    // 0 0 3 1
    // 0 0 1 3
    newstate_vector[3] = field_multiply(state_vector[3],3)
      ^ field_multiply(state_vector[2],1);
    newstate_vector[2] = field_multiply(state_vector[2],3)
      ^ field_multiply(state_vector[3],1);
    newstate_vector[1] = field_multiply(state_vector[1],3)
      ^ field_multiply(state_vector[0],1);
    newstate_vector[0] = field_multiply(state_vector[0],3)
      ^ field_multiply(state_vector[1],1);

    for (int i = 3 ; i >= 0; i--)
      newstate = (newstate << 2) | newstate_vector[i];
    state = newstate;
  }
  /*
   * The debug generic printout routine. Only makes noise if verbose
   * set.
   */
  private void pdebug(String format, int ... args) {
    if (!verbose)
      return;
    switch (args.length) {
      case 0:
        System.out.printf(format);
        break;
      case 1:
        System.out.printf(format, args[0]);
        break;
      case 2:
        System.out.printf(format, args[0], args[1]);
        break;
      case 3:
        System.out.printf(format, args[0], args[1], args[2]);
        break;
      case 4:
        System.out.printf(format, args[0], args[1], args[2], args[3]);
        break;
    }
  }
  /*
   * encryption method applied to state
   */
  private void encrypt() {
    // 0
    pdebug("E state: %04o\n", state);
    interstate[0] = state;
    // 1
    state ^= roundkeys[0];
    pdebug("E Add round key: %04o\n", state);
    interstate[1] = state;
    // 2
    substitute_nibble();
    // code groups of 4 bits
    pdebug("E Substitute: %04o\n", state);
    interstate[2] = state;
    // 3
    swaprow();
    // swap 0,2 groups
    pdebug("E Swap rows: %04o\n", state);
    interstate[3] = state;
    // 4
    mixcolumns();
    // matrix multiply, preserves groups of 8 bits
    pdebug("E Mix Columns: %04o\n", state);
    interstate[4] = state;
    // 5
    state ^= roundkeys[1];
    // hurr .. add a constant
    pdebug("E Add round key: %04o\n", state);
    interstate[5] = state;
    // 6
    substitute_nibble();
    // SECOND coding!
    pdebug("E Substitute: %04o\n", state);
    interstate[6] = state;
    // 7
    swaprow();
    // swap 0,2 groups
    pdebug("E Swap rows: %04o\n", state);
    interstate[7] = state;
    // 8
    state ^= roundkeys[2];
    // .. add another constant
    pdebug("E Add round key: %04o\n", state);
    interstate[8] = state;
  }
  /*
   * decryption method applied to state
   */
  private void decrypt() {
    // 0
    pdebug("D state: %04o\n", state);
    inverstate[0] = state;
    // 1
    state ^= roundkeys[2];
    pdebug("D Add round key: %04o\n", state);
    inverstate[1] = state;
    // 2
    swaprow();
    pdebug("D Swap rows: %04o\n", state);
    inverstate[2] = state;
    // 3
    inv_substitute_nibble();
    pdebug("D Substitute: %04o\n", state);
    inverstate[3] = state;
    // 4
    state ^= roundkeys[1];
    // hurr .. add a constant
    pdebug("D Add round key: %04o\n", state);
    inverstate[4] = state;
    // 5
    inv_mixcolumns();
    pdebug("D Mix Columns: %04o\n", state);
    inverstate[5] = state;
    // 6
    swaprow();
    pdebug("D Swap rows: %04o\n", state);
    inverstate[6] = state;
    // 7
    inv_substitute_nibble();
    pdebug("D Substitute: %04o\n", state);
    inverstate[7] = state;
    // 8
    state ^= roundkeys[0];
    pdebug("D Add round key: %04o\n", state);
    inverstate[8] = state;
  }
  /*
   * set in order to make more noise
   */
  public void setverbose() {
    verbose = true;
  }
  /*
   * set in order to make less noise
   */
  public void setquiet() {
    verbose = false;
  }
  /*
   * encryption method applied to a 8-bit plaintext
   */
  public byte ecb_encrypt(byte input_block) {
    state = input_block & 0xff;
    encrypt();
    return (byte)state;
  }
  /*
   * decryption method applied to a 8-bit ciphertext
   */
  public byte ecb_decrypt(byte cipherblock) {
    state = cipherblock & 0xff;
    decrypt();
    return (byte)state;
  }
  /*
   * constructor for a cipher object from a 8-bit key
   */
  public simple_aes8(byte key) {
    setkey(key);
  }
  /*
   * encrypt and decrypt random 8-bit text 100 times
   */
  static public void main(String [] args) {
    // 8-bit key
    byte key
      = (byte)(256 * Math.random());
    int ntests = 1000;
    int errs
      = 0;
    simple_aes8 aes
      = new simple_aes8(key);
    System.out.println("Testing 8-bit encryption/decryption:");
    for (int i = 0; i < ntests; i++) {
      // 8-bit text
      byte text1
        = (byte)(256 * Math.random());
      byte ciphertext1 = (byte)(aes.ecb_encrypt(text1) & 0xff);
      byte text2
        = aes.ecb_decrypt(ciphertext1);
      if (text1 != text2) {
        System.out.printf("\nmistake with key %04o\n", key);
        System.out.printf("in: %d, out:%d\n",
            text1 & 255, text2 & 255);
        errs++;
      }
    }
    System.out.println("\r" + errs + "/" + ntests + " errors");
    if (errs > 0)
      System.exit(1);
  }
}
// end of class

