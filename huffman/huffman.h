#pragma once
#ifndef _HUFFMAN_H
#define _HUFFMAN_H

typedef struct bnode
{
	unsigned int freq;
	unsigned char alpha_index;
	char* prefix;
	struct bnode* parent;
	struct bnode* left_child;
	struct bnode* right_child;

} t_bnode;

typedef struct huffman_tree
{
	t_bnode* end_nodes;
	unsigned int size_of_end_nodes;
} t_htree;


int init_hufftree(char*, unsigned int, t_htree*);
int complete_hufftree(t_htree*);
int deinit_hufftree(t_htree*);
int huffman_code(int, int);
int huffman_decode(int, int);
int write_bits(char*, int, char*);
int read_bit(char*, int);

#endif
