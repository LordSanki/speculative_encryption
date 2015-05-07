#ifndef __SIMPLE_AES_8_H__
#define __SIMPLE_AES_8_H__

#include <iostream>
#include <cstdio>
#include <string>
#include <cstdlib>

typedef unsigned char byte;
struct aes8_key_type{
	byte roundkey[3];
};

class simple_aes8 {
public:

private:
	// 0->2->3->0; 1-1
	// permutation used in encryption
	byte sbox[4];

	// 0->3->2->0; 1->1;
	// inverse permutation
	byte invsbox[4];

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
	}
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
	protected:
	byte encrypt(byte state, aes8_key_type rk) {

		// 1
		state ^= rk.roundkey[0];
		// 2
		state = substitute_nibble(state);
		// code groups of 4 bits
		// 3
		state = swaprow(state);
		// swap 0,2 groups
		// 4
		state = mixcolumns(state);
		// matrix multiply, preserves groups of 8 bits
		// 5
		state ^= rk.roundkey[1];
		// add a constant
		// 6
		state = substitute_nibble(state);
		// SECOND coding!
		// 7
		state = swaprow(state);
		// swap 0,2 groups
		// 8
		state ^= rk.roundkey[2];
		// .. add another constant
		return state;
	}
	/*
	* decryption method applied to state
	*/
	byte decrypt(byte state, aes8_key_type rk) {
		// 1
		state ^= rk.roundkey[2];
		// 2
		state = swaprow(state);
		// 3
		state = inv_substitute_nibble(state);
		// 4
		state ^= rk.roundkey[1];

		// add a constant
		// 5
		state = inv_mixcolumns(state);
		// 6
		state = swaprow(state);
		// 7
		state = inv_substitute_nibble(state);
		// 8
		state ^= rk.roundkey[0];
		return state;
	}
	/*
	* set in order to make more noise
	*/
public:
	aes8_key_type generate_key(byte key) {
		//if (this->key == key)
		//return;
		aes8_key_type rk;
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
		return rk;
	}
	/*
	* encryption method applied to a 8-bit plaintext
	*/
	virtual byte ecb_encrypt(byte input_block, aes8_key_type rk) {
		byte state = input_block & 0xff;
		state = encrypt(state, rk);
		return state;
	}
	/*
	* decryption method applied to a 8-bit ciphertext
	*/
	virtual byte ecb_decrypt(byte cipherblock, aes8_key_type rk) {
		byte state = cipherblock & 0xff;
		state = decrypt(state, rk);
		return state;
	}

	virtual void cbc_encrypt(const void *_in, void *_out, long len, aes8_key_type rk) {
		byte iv = 0;
		byte *in = (byte*)_in;
		byte *out = (byte*)_out;
		for (long n = 0; n < len; n++) {
			out[n] = encrypt(in[n] ^ iv, rk);
			iv = out[n];
		}
	}
	virtual void cbc_decrypt(const void *_in, void *_out, long len, aes8_key_type rk) {
		byte iv = 0;
		byte *in = (byte*)_in;
		byte *out = (byte*)_out;
		for (long n = 0; n < len; n++){
			out[n] = decrypt(in[n], rk) ^ iv;
			iv = in[n];
		}
	}

	simple_aes8()
	{
		sbox[0] = 3;
		sbox[1] = 1;
		sbox[2] = 0;
		sbox[3] = 2;

		invsbox[0] = 2;
		invsbox[1] = 1;
		invsbox[2] = 3;
		invsbox[3] = 0;
	}
	bool self_unit_test()
	{
		using namespace std;
		// 8-bit key
		int ntests = 1000;
		int errs = 0;
		simple_aes8 aes;
		aes8_key_type key = aes.generate_key((byte)(rand() % 256));
		for (int i = 0; i < ntests; i++) {
			// 8-bit text
			byte text1 = (byte)(256 * rand());
			byte ciphertext1 = (byte)(aes.ecb_encrypt(text1, key) & 0xff);
			byte text2 = aes.ecb_decrypt(ciphertext1, key);
			if (text1 != text2) {
				errs++;
			}
		}
		byte t1[10];
		byte t2[10];
		byte t3[10];
		for (int i = 0; i < ntests; i++) {
			for (int j = 0; j < 10; j++)
				t1[j] = (byte)(rand() % 256);
			aes.cbc_encrypt(t1, t2, 10, key);
			aes.cbc_decrypt(t2, t3, 10, key);
			for (int j = 0; j < 10; j++){
				if (t1[j] != t3[j]){
					errs++;
					break;
				}
			}
		}
		if (errs > 0)
			return false;
		else
			return true;
	}
};

#endif //__SIMPLE_AES_8_H__
