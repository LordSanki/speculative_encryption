#include <simple_aes8.h>
#include <helper.h>
#include <cstdio>
#include <iostream>

using namespace std;

class spec_aes8 :public simple_aes8
{
public:
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
};
typedef unsigned char uchar;
int main()
{
	spec_aes8 aes;
	if (false == aes.self_unit_test()) return -1;

	uchar * in = NULL;
	long nbytes = helper::read_file("jc.txt", (void**)&in);
	if (nbytes < 1){ cout << "Error Opening File\n"; getchar(); return -1; }
	uchar *enc = new uchar[nbytes];
	uchar *dec = new uchar[nbytes];

	aes8_key_type key = aes.generate_key(255);
	aes.cbc_encrypt(in, enc, nbytes, key);
	aes.cbc_decrypt(enc, dec, nbytes, key);

	double state_feasability[256] = { 0 };
	//compute_feasability();
	long count = 0;
	for (long i = 1; i < nbytes; i++){
		if (in[i] == 'a'&& in[i-1] == ' ')
			hash[enc[i]]++;
	}
	for (int i = 0; i < 256; i++){
		cout << i << ":" << hash[i] << " \n ";
	}
	cout << endl;

	/*
	for (long i = 0; i < nbytes; i++){
		if (in[i] != dec[i]){
			cout << "Error in encryption\n";
			getchar(); return -1;
		}
	}
	*/
	delete[] enc;
	delete[] in;
	delete[] dec;

	getchar();
	return 0;
}

