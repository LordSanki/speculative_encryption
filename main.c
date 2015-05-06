#include <cbc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define REP 1
long read_file(char * path, char ** buff);

int main(int argc, char **argv)
{
  char * msg =NULL, *msg2=NULL, *msg3= NULL;
  const char * def = "0123456789012345";
  long size=0;
  char * out;
  char ivec[16] = {0};
  int i;
  int match;
  int count;
  AES_KEY key;
  if(argc >= 2)
    size = read_file(argv[1], &msg);
  if(size == 0){
    size = 16*REP;
    msg = (char*) def;
    msg = (char*)malloc(size+1);
    for(i=0; i<REP; i++)
      memcpy(&msg[i*16], def, 16);
    msg[size]=0;
  }
  out = (char*)malloc(size+1);
  msg2 = (char*)malloc(size+1);
  msg3 = (char*)malloc(size+1);
  msg2[size]=0;
  out[size]=0;
#if 0

  // Encryption
  private_AES_set_encrypt_key("password", 128, &key);
  Ident_cbc_encrypt(msg, out, size, &key, ivec, 1);
  //AES_cbc_encrypt(msg, out, size, &key, ivec, 1);
#if 0
   // Decryption
  private_AES_set_decrypt_key("password", 128, &key);
  memset(ivec, 0, 16);
  Ident_cbc_encrypt(out, msg2, size, &key, ivec, 0);
  //AES_cbc_encrypt(out, msg2, size, &key, ivec, 0);

  printf("%s\n%s\n",msg,msg2);
#endif
#endif

#if 1
  // Encryption
  private_AES_set_encrypt_key("password", 128, &key);
  //Ident_cbc_encrypt(msg, out, size, &key, ivec, 1);
  AES_cbc_encrypt(msg, out, size, &key, ivec, 1);
  
  memset(ivec, 0, 16);
  msg[0] = msg[0]^1;
  AES_cbc_encrypt(msg, msg2, size, &key, ivec, 1);

  match = 0;
  count =0;
  for(i=0; i<size; i++){
    if(msg2[i] == out[i])
    {
      match = 1;
      //printf("length found for 8 bits \n");
      count ++;
      //break;
    }
  }
  if(match == 1)
      printf("length found for 8 bits %d/%d\n", count, size);

  for(i=0; i<size; i++){
    short * a = (short *)&msg2[i];
    short * b = (short *)&out[i];
    if(a[0] == b[0])
    {
      match = 1;
      //printf("length found  for 16 bits \n");
      //break;
    }
  }
  for(i=0; i<size; i++){
    int * a = ( int*)&msg2[i];
    int * b = ( int*)&out[i];
    if(a[0] == b[0])
    {
      match = 1;
      printf("length found  for 32 bits \n");
      //break;
    }
  }
  for(i=0; i<size; i++){
    long long int * a = (long long int*)&msg2[i];
    long long int * b = (long long int*)&out[i];
    if(a[0] == b[0])
    {
      match = 1;
      printf("length found  for 64 bits \n");
      //break;
    }
  }
  if(match == 0)
    printf("length not found\n");
#if 0
  msg[0] = (msg[0]^1)&1;
  for(i=1; i<16*REP; i++) 
    msg[i] = 0;
  AES_cbc_encrypt(msg, msg3, size, &key, ivec, 1);

  for(i=0; i<16*REP; i++) 
    printf("%d:%d:%d\n",(int)out[i], (int)msg2[i], (int)msg3[i]);
#endif
#endif

#if 0
  // Decryption
  private_AES_set_decrypt_key("password", 128, &key);
  memset(ivec, 0, 16);
  //Ident_cbc_encrypt(out, msg2, size, &key, ivec, 0);
  AES_cbc_encrypt(out, msg2, size, &key, ivec, 0);

  printf("%s\n%s\n",msg,msg2);
#endif

  free(msg);
  free(out);
  free(msg2);
  return 0;
}

long read_file(char * path, char **buff)
{
  FILE* f = fopen(path, "rb");
  long int size;
  if(f == NULL)
    return 0;
  fseek(f, 0, SEEK_END);
  size = ftell(f);
  fseek(f, 0, SEEK_SET);
  *buff = (char*)malloc(size);
  fread(*buff, 1, size, f);
  fclose(f);
  return size;
}


