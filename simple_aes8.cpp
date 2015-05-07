#include <simple_aes8.h>
#include <helper.h>
#include <cstdio>
#include <iostream>
#include <time.h>
#include <bitset>
#include <algorithm>
#define DEF_KEY 255

using namespace std;

#define MAX_CONV_LEN_SEARCH 1000l
#define TEST_8_BIT_LEN 40000l
#define TEST_2_BIT_LEN 20000l
#define LOOK_BACK_LEN 8l

typedef unsigned char uchar;
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
struct cbc2_key{
  bitset<2> rk;
};
class spec_cbc2
{
  typedef bitset<8> byte;
  typedef bitset<2> block;
  private:
  block encrypt(block in, cbc2_key key){
    block rk =  key.rk;
    block b; b[0] = in[0]^rk[0]; b[1] = in[1]^rk[1];
    return b;
  }
  block decrypt(block in, cbc2_key key){
    block rk =  key.rk;
    block b; b[0] = in[0]^rk[0]; b[1] = in[1]^rk[1];
    return b;
  }
  public:
  void cbc_encrypt(const void *_in, void *_out, long len,  cbc2_key key)
  {
    uchar * in = (uchar*)_in;
    uchar * out = (uchar*)_out;
    block iv = 0;
    for(long l=0; l<len; l++){
      byte inb = byte(in[l]);
      byte outb;
      for(int i=0; i<8; i+=2)
      {
        block bli, blo;
        bli[0] = inb[i]^iv[0];
        bli[1] = inb[i+1]^iv[1];
        blo = encrypt(bli, key);
        outb[i] = blo[0];
        outb[i+1] = blo[1];
        iv = blo;
      }
      out[l] = (uchar)outb.to_ulong();
    }
  }
  void cbc_decrypt(const void *_in, void *_out, long len,  cbc2_key key)
  {
    uchar * in = (uchar*)_in;
    uchar * out = (uchar*)_out;
    block iv = 0;
    for(long l=0; l<len; l++){
      byte inb = byte(in[l]);
      byte outb;
      for(int i=0; i<8; i+=2)
      {
        block bli, blo;
        bli[0] = inb[i];
        bli[1] = inb[i+1];
        blo = decrypt(bli, key);
        outb[i] = blo[0]^iv[0];
        outb[i+1] = blo[1]^iv[1];
        iv = bli;
      }
      out[l] = (uchar)outb.to_ulong();
    }
  }
  cbc2_key generate_key(){ cbc2_key key; key.rk[0] = 1; key.rk[1] = 1; return key;}
};

void compute_feasability2(uchar *in, long len, double *res, long states)
{
  for(long i=0; i<states; i++){
    res[i] = 0;
  }

  bitset<8> byte;
  bitset<2> block;
  for(long i=0; i<len; i++){
    byte = in[i];
    for(int j=0; j<8; j+=2){
      block[0] = byte[j];
      block[1] = byte[j+1];
      res[block.to_ulong()]++;
    }
  }
  for(long i=0; i<states; i++){
    res[i] = (res[i]/(len*4))*100;
  }
}

double find_prediction_acc_with_lookback(uchar *in, uchar *enc, long len, int lblen)
{
  typedef bitset<8> byte;
  typedef bitset<2> block;
  spec_cbc2 cbc;
  cbc2_key k = cbc.generate_key();
  double count = 0;
  double correct = 0;
  int nbytes = ((lblen-1)/4)+1;
  uchar *out = new uchar [nbytes];
  for(long l=nbytes; l<len; l++)
  {
    cbc.cbc_encrypt(&in[l], out, nbytes, k);
    byte b1 = out[nbytes-1]; byte b2 = enc[l+nbytes-1];
    block bl1, bl2;
    bl1[0] = b1[6]; bl2[0] = b2[6];
    bl1[1] = b1[7]; bl2[1] = b2[7];
    if(bl1 == bl2){
      correct++;
    }
    count++;
  }
  delete[] out;
  return (correct/count)*100;
}

void compute_feasability(uchar *in, long len, double *res, long states)
{
  for(long i=0; i<states; i++){
    res[i] = 0;
  }
  for(long i=0; i<len; i++){
    res[in[i]]++;
  }
  for(long i=0; i<states; i++){
    res[i] = (res[i]/len)*100;
  }
}

double find_avg_conv_length(uchar* in, long max)
{
  spec_aes8 aes; aes8_key_type key = aes.generate_key(DEF_KEY);
  uchar *out1 = new uchar[max];
  uchar *out2 = new uchar[max];
  aes.cbc_encrypt(in, out1, max, key);
  uchar org = in[1];
  long count=0;
  for(int i=0; i<256; i++){
    if(org != i){
      in[1] = (uchar)i;
      aes.cbc_encrypt(in, out2, max, key);
      long j;
      for(j=1; j<max; j++){
        if(out1[j] == out2[j]){
          count += j;
          break;
        }
      }
      if(j == max) count += max;
    }
  }
  delete[] out1;
  delete[] out2;
  return count/255.0;
}

bool find_impossible_states(uchar* in, uchar *enc, long len, uchar state, double *prob )
{
  bool found = false;
  double count=0;
  long hash[256] = {0};
  for(long l=0; l<len; l++){
    if(state == in[l]){
      hash[enc[l]]++;
      count++;
    }
  }
  if(count > 0.0){
    for(int i=0; i<256; i++){
      if(prob)
        prob[i] = (hash[i]/count)*100;
      if(hash[i] == 0 )
        found = true;
    }
  }
  return found;
}

int main()
{
	spec_aes8 aes;
	if (false == aes.self_unit_test()) return -1;

	uchar * in = NULL;
	long numbytes = helper::read_file("jc.txt", (void**)&in);
	if (numbytes < 1){ cout << "Error Opening File\n"; getchar(); return -1; }
  cout <<"\n"<<numbytes<<" bytes read from file\n\n";
	uchar *enc = new uchar[numbytes];
	uchar *dec = new uchar[numbytes];


#if 1
  long nbytes = min(numbytes, TEST_8_BIT_LEN);
	aes8_key_type key = aes.generate_key(DEF_KEY);

  helper::timer enc_timer;
  enc_timer.start();
	aes.cbc_encrypt(in, enc, nbytes, key);
  enc_timer.stop();
  cout << "8 Bit Serial Encryption Time: " << enc_timer.value() <<"us\n\n";
	aes.cbc_decrypt(enc, dec, nbytes, key);

	double state_feasability[256] = { 0 };
	compute_feasability(enc, nbytes, state_feasability, 256);

  cout << "============== 8 bit Feasability Analysis(%) ============\n";
  for (int i = 0; i < 256; i++){
		cout << i << " : " << state_feasability[i] << "\t";i++;
		cout << i << " : " << state_feasability[i] << "\t";i++;
		cout << i << " : " << state_feasability[i] << "\t";i++;
		cout << i << " : " << state_feasability[i] << " \n ";
	}
  cout << "===================================================\n";

  int max_len = MAX_CONV_LEN_SEARCH;
  cout << "===== 8 bit Avg Merging length ("<<max_len<<" is infifnity) ======\n";
  cout << "\t\t" << find_avg_conv_length(in, max_len)<<"\n";
  cout << "===================================================\n";

  cout << "============== 8 bit Character Probability ============\n";
  double prob[256];
  if(find_impossible_states(in, enc, nbytes, (uchar)'a', prob))
    cout <<" Found Impossible state\n";
  else
    cout <<" Could not find impossible states\n";
  for (int i = 0; i < 256; i++){
		cout << i << " : " << prob[i] << "\t";i++;
		cout << i << " : " << prob[i] << "\t";i++;
		cout << i << " : " << prob[i] << "\t";i++;
		cout << i << " : " << prob[i] << " \n ";
	}
  cout << "===================================================\n";
#endif
  spec_cbc2 cbc;

  int len2 = min(numbytes, TEST_2_BIT_LEN);
  cbc2_key k= cbc.generate_key();
  cbc.cbc_encrypt(in, enc, len2, k);
  cbc.cbc_decrypt(enc, dec, len2, k);

  double state_feasability2[4] = { 0 };
  compute_feasability2(enc, len2, state_feasability2, 4);

  cout << "============== 2 bit Feasability Analysis(%) ============\n";
  for (int i = 0; i < 4; i++){
    cout << i << " : " << state_feasability2[i] << "\t";i++;
    cout << i << " : " << state_feasability2[i] << "\t";i++;
    cout << i << " : " << state_feasability2[i] << "\t";i++;
    cout << i << " : " << state_feasability2[i] << " \n ";
  }
  cout << "===================================================\n";
  
  int lookback_len = LOOK_BACK_LEN;
  double prediction = find_prediction_acc_with_lookback(in, enc, len2, lookback_len);

  cout << "============== 2 bit Prediction Rate ============\n";
  cout << " Look back length: "<<lookback_len<<"\n";
  cout << " Prediction acc: "<<prediction<<"\n";
  cout << "===================================================\n";

	delete[] enc;
	delete[] in;
	delete[] dec;

  fprintf(stderr, "Press return key to exit\n");
	getchar();
	return 0;
}

