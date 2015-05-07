#include <iostream>
#include <cstdio>
#include <string>
using namespace std;
typedef unsigned char byte;
// 0->2->3->0; 1-1
// permutation used in encryption
static unsigned int sbox[] = { 3, 1, 0, 2 };

// 0->3->2->0; 1->1;
// inverse permutation
static unsigned int invsbox[] = { 2, 1, 3, 0 };


class simple_aes8 {
public:
	typedef unsigned char byte;
	struct key_type{
		byte roundkey[3];
	};
private:
	//byte key;
	//byte roundkeys[3]; // 8-bit key


	//byte state;

	//int interstate[9];
	//int inverstate[9]; // debugging encryption process
	// debugging decryption process
	/*
	* Multiplication in GF(4). Field elements are integers in the range
	* 0...3, which we think of as degree < 2 polynomials over GF(2).
	* a1 a0 * b1 b0 =
	* .. (b1b0+b1b1+b0b1)(a0b0+b1b1)
	* (X**2 = X+1) since X**2+X+1 is irreducible mod 2.
	*/
	byte field_multiply(byte a, byte b) {
		byte ret = 0;
		byte xmultiples[2]; // a, a*x
		xmultiples[0] = a;
		for (int i = 1; i < 2; i++) // a*x^1 = x*(a*x^0)
			xmultiples[i] = x_multiply(xmultiples[i - 1]);
		for (int i = 0; i < 2; i++) {
			if ((b & 1) != 0)
				ret ^= xmultiples[i]; // b0*a+b1*a*x = b*a
			b = b >> 1;
			//b >> >= 1;
		}
		return ret;
	}
	/*
	* Multiplication by the element x (= 1*x+0*1 = "10") of the field
	*/
	byte x_multiply(byte a) {
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
		return -1;
		//throw new NullPointerException();
	}
	/*
	* Make and install the derived keys from the original key
	*/

	/*
	* Apply a subsitution in each of 4 groups of 2 bits each ("nibbles")
	* to the state.
	*/
	byte substitute_nibble(byte state) {
		// apply sbox permutation to each nibble
		byte state_vector[4]; // each is 2 bit!
		byte newstate = 0;
		for (int i = 0; i < 4; i++) {
			state_vector[i] = sbox[state & 0x3]; // 2 bit
			//state >> >= 2;
			state = state >> 2;
		}
		for (int i = 3; i >= 0; i--)
			newstate = (newstate << 2) | state_vector[i];
		//state = newstate;
		return newstate;
	}
	/*
	* Apply inverse subsitution in each of 4 groups of 2 bits each ("nibbles")
	* to the state.
	*/
	byte inv_substitute_nibble(byte state) {
		// apply inverse sbox permutation to each nibble
		byte state_vector[4];
		byte newstate = 0;
		for (int i = 0; i < 4; i++) {
			state_vector[i] = invsbox[state & 0x3]; // 2 bit
			state = state >> 2;
		}
		for (int i = 3; i >= 0; i--)
			newstate = (newstate << 2) | state_vector[i];
		//state = newstate;
		return newstate;
	}
	/*
	* Permute the nibbles. (x0,x1,x2,x3) -> (x2,x3,x0,x3)
	* to the state.
	*/
	byte swaprow(byte state) {
		byte state_vector[4];
		byte newstate = 0;
		for (int i = 0; i < 4; i++) {
			state_vector[i] = state & 0x3;
			state = state >> 2;
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
		//state = newstate;
		return newstate;
	}
	/*
	* Apply a linear transform to the state as a vector of 4 nibbles
	*/
	byte mixcolumns(byte state) {
		byte state_vector[4];// = new int[4]; // 2 bits each
		byte newstate = 0;
		byte oldstate = state;
		byte newstate_vector[4];// = new int[4];
		for (int i = 0; i < 4; i++) {
			state_vector[i] = state & 0x3; // 2 bits
			//state >> >= 2;
			state = state >> 2;
		}
		// matrix multiplication on groups of 2 bits
		// 1 2 0 0
		// 2 1 0 0
		// 0 0 1 2
		// 0 0 2 1
		newstate_vector[3] = state_vector[3]
			^ field_multiply(state_vector[2], 2);
		newstate_vector[2] = state_vector[2]
			^ field_multiply(state_vector[3], 2);
		newstate_vector[1] = state_vector[1]
			^ field_multiply(state_vector[0], 2);
		newstate_vector[0] = state_vector[0]
			^ field_multiply(state_vector[1], 2);

		for (int i = 3; i >= 0; i--)
			newstate = (newstate << 2) | newstate_vector[i];
		return newstate;
		//state = newstate;
	}
	/*
	* Apply inverse linear transform to the state as a vector of 4 nibbles
	*/
	byte inv_mixcolumns(byte state) {
		byte state_vector[4];// = new int[4];
		byte newstate = 0;
		byte newstate_vector[4];// = new int[4];
		for (int i = 0; i < 4; i++) {
			state_vector[i] = state & 0x3;
			//state >> >= 2;
			state = state >> 2;
		}
		// matrix multiplication on groups of 2 bits
		// 3 1 0 0
		// 1 3 0 0
		// 0 0 3 1
		// 0 0 1 3
		newstate_vector[3] = field_multiply(state_vector[3], 3)
			^ field_multiply(state_vector[2], 1);
		newstate_vector[2] = field_multiply(state_vector[2], 3)
			^ field_multiply(state_vector[3], 1);
		newstate_vector[1] = field_multiply(state_vector[1], 3)
			^ field_multiply(state_vector[0], 1);
		newstate_vector[0] = field_multiply(state_vector[0], 3)
			^ field_multiply(state_vector[1], 1);

		for (int i = 3; i >= 0; i--)
			newstate = (newstate << 2) | newstate_vector[i];
		//state = newstate;
		return newstate;
	}

	/*
	* encryption method applied to state
	*/
	byte encrypt(byte state, key_type rk) {

		//byte interstate[9];
		//		byte inverstate[9];
		// 0
		//interstate[0] = state;
		// 1
		state ^= rk.roundkey[0];
		//interstate[1] = state;
		// 2
		state = substitute_nibble(state);
		// code groups of 4 bits
		//interstate[2] = state;
		// 3
		state = swaprow(state);
		// swap 0,2 groups
		//interstate[3] = state;
		// 4
		state = mixcolumns(state);
		// matrix multiply, preserves groups of 8 bits
		//interstate[4] = state;
		// 5
		state ^= rk.roundkey[1];
		// add a constant

		//interstate[5] = state;
		// 6
		state = substitute_nibble(state);
		// SECOND coding!
		///interstate[6] = state;
		// 7
		state = swaprow(state);
		// swap 0,2 groups
		//interstate[7] = state;
		// 8
		state ^= rk.roundkey[2];
		// .. add another constant
		//interstate[8] = state;
		return state;
	}
	/*
	* decryption method applied to state
	*/
	byte decrypt(byte state, key_type rk) {
		//		byte interstate[9];
		//byte inverstate[9];
		// 0
		//inverstate[0] = state;
		// 1
		state ^= rk.roundkey[2];
		//inverstate[1] = state;
		// 2
		state = swaprow(state);
		//inverstate[2] = state;
		// 3
		state = inv_substitute_nibble(state);
		///inverstate[3] = state;
		// 4
		state ^= rk.roundkey[1];

		// add a constant
		//inverstate[4] = state;
		// 5
		state = inv_mixcolumns(state);
		//inverstate[5] = state;
		// 6
		state = swaprow(state);
		//inverstate[6] = state;
		// 7
		state = inv_substitute_nibble(state);
		//inverstate[7] = state;
		// 8
		state ^= rk.roundkey[0];
		//		inverstate[8] = state;
		return state;
	}
	/*
	* set in order to make more noise
	*/
public:
	key_type generate_key(byte key) {
		//if (this->key == key)
		//return;
		key_type rk;
		byte w[6];
		// 4 bits each
		w[0] = (key >> 4) & 0xf;
		// upper 4 bits of key
		w[1] = key & 0xf;
		// lower 4 bits of key
		w[2] = w[0] ^ (2 * 4)
			// 4 bits
			^ ((sbox[w[1] & 0x3] << 2) | sbox[w[1] >> 2]); // 4 bits
		w[3] = w[1] ^ w[2];
		// 4 bits
		w[4] = w[2] ^ (3 * 4)
			// 4 bits
			^ ((sbox[w[3] & 0x3] << 2) | sbox[w[3] >> 2]); // 4 bits
		w[5] = w[3] ^ w[4];
		// 4 bits
		rk.roundkey[0] = (byte)(key & 0xff);
		rk.roundkey[1] = (byte)((w[2] << 4) | w[3]);
		rk.roundkey[2] = (byte)((w[4] << 4) | w[5]);
		// 8 bits
		// 8 bits
		// 8 bits
		// those roundkeys seem to have independent 4 bit components
		//this->key = key;
		return rk;
	}
	/*
	* encryption method applied to a 8-bit plaintext
	*/
	byte ecb_encrypt(byte input_block, key_type rk) {
		byte state = input_block & 0xff;
		state = encrypt(state, rk);
		return state;
	}
	/*
	* decryption method applied to a 8-bit ciphertext
	*/
	byte ecb_decrypt(byte cipherblock, key_type rk) {
		byte state = cipherblock & 0xff;
		state = decrypt(state, rk);
		return state;
	}

	void cbc_encrypt(const byte *in, byte *out, long len, key_type rk) {
		byte iv = 0;
		for (long n = 0; n < len; n++) {
			//iv = in[n] ^ iv;
			out[n] = encrypt(in[n] ^ iv, rk);
			iv = out[n];
		}
	}
	void cbc_decrypt(const byte *in, byte *out, long len, key_type rk) {
		byte iv = 0;
		for (long n = 0; n < len; n++){
			//byte t = decrypt(in[n], rk);
			//(*block) (in, tmp.c, key);
			//byte c = in[n];
			out[n] = decrypt(in[n], rk) ^ iv;
			iv = in[n];
		}
	}
	/*
	* constructor for a cipher object from a 8-bit key
	*/
	//simple_aes8(byte key) {
	//setkey(key);
	//}
	/*
	* encrypt and decrypt random 8-bit text 100 times
	*/
};

int main(int argc, char *argv) {
	// 8-bit key
	typedef unsigned char Text_Type;
	int ntests = 1000;
	int errs = 0;
	simple_aes8 aes;// = simple_aes8(key);
	simple_aes8::key_type key = aes.generate_key((simple_aes8::byte)(256 * rand()));
	cout << "Testing 8-bit encryption/decryption:";
	for (int i = 0; i < ntests; i++) {
		// 8-bit text
		Text_Type text1
			= (Text_Type)(256 * rand());
		Text_Type ciphertext1 = (byte)(aes.ecb_encrypt(text1, key) & 0xff);
		Text_Type text2 = aes.ecb_decrypt(ciphertext1, key);
		if (text1 != text2) {
			printf("\nmistake with key %04o\n", key);
			printf("in: %d, out:%d\n", (int)text1 & 255, (int)text2 & 255);
			errs++;
		}
	}
	Text_Type t1[10];
	Text_Type t2[10];
	Text_Type t3[10];
	for (int i = 0; i < ntests; i++) {
		for (int j = 0; j < 10; j++)
			t1[j] = (Text_Type)(rand() % 256);
		aes.cbc_encrypt(t1, t2, 10, key);
		aes.cbc_decrypt(t2, t3, 10, key);
		for (int j = 0; j < 10; j++){
			if (t1[j] != t3[j]){
				errs++;
				break;
			}
		}
	}
	cout << "\n" << errs << "/" << ntests << " errors";
	char c;
	cin >> c;
	if (errs > 0)
		return -1;
	return 0;
}
// end of class

