#ifndef __HELPER_H__
#define __HELPER_H__

#include <cstdio>
#include <time.h>
struct helper{
	static long read_file(char * path, void **buff)
	{
		unsigned char ** b = (unsigned char**)buff;
		FILE* f = fopen(path, "rb");
		long int size;
		if (f == NULL)
			return 0;
		fseek(f, 0, SEEK_END);
		size = ftell(f);
		fseek(f, 0, SEEK_SET);
		*b = new unsigned char[size];
		fread(*buff, 1, size, f);
		fclose(f);
		return size;
	}
  struct timer{
    timespec st, en;
    inline void start() {
      clock_gettime(CLOCK_REALTIME, &st);
    }
    inline void stop() {
      clock_gettime(CLOCK_REALTIME, &en);
    }
    long double value() {
      long double acc = (en.tv_sec - st.tv_sec);
      acc *= 1E6;
      acc += ((en.tv_nsec - st.tv_nsec)/1E3);
      //acc += ((en.tv_nsec - st.tv_nsec)/1E9);
      return acc;
    }
  };
};

#endif
