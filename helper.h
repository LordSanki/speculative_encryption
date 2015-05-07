#ifndef __HELPER_H__
#define __HELPER_H__

#include <cstdio>

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
};

#endif