#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "huffman.h"

int usage(void)
{
	printf("coding:   huffman -c in_file_name out_file_name\n");
	printf("decoding: huffman -d out_file_name decode_file_name\n");

	return 0;
}


int main(int argc, char* argv[])
{

	int in_file, out_file, decode_file;

	if (argc > 2)
	{
		if (!strcmp(argv[1], "-c"))
		{
			in_file = open(argv[2], O_CREAT | O_RDWR | O_BINARY, S_IREAD | S_IWRITE);
			out_file = open(argv[3], O_CREAT | O_RDWR | O_BINARY | O_TRUNC, S_IREAD | S_IWRITE);
			huffman_code(in_file, out_file);
			close(in_file);
			close(out_file);
		}
		else if (!strcmp(argv[1], "-d"))
		{
			out_file = open(argv[2], O_CREAT | O_RDWR | O_BINARY, S_IREAD | S_IWRITE);
			decode_file = open(argv[3], O_CREAT | O_RDWR | O_BINARY | O_TRUNC, S_IREAD | S_IWRITE);
			huffman_decode(out_file, decode_file);
			close(decode_file);
			close(out_file);
		}
		else usage();
	}
	else usage();

	return 0;
}
