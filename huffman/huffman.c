#include <string.h>
#include <stdlib.h>
#include  <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "huffman.h"

int reverse(char* str)
{
	int i;
	char tmp;
	int len = strlen(str);

	for (i = 0; i < len - i - 1;i++)
	{
		tmp = str[i];
		str[i] = str[len - i - 1];
		str[len - i - 1] = tmp;
	}
	return 0;
}

int complete_hufftree(t_htree* h_tree)
{
	unsigned int i, j, f_i, f_j, full_sum = 0, sum;
	char* tmp_prefix = NULL;

	t_bnode* tmp_node = NULL;
	t_bnode* tmp_i = NULL;
	t_bnode* tmp_j = NULL;
	t_bnode* f_tmp_i = NULL;
	t_bnode* f_tmp_j = NULL;

	for (i = 0;i < h_tree->size_of_end_nodes;i++)
		full_sum += h_tree->end_nodes[i].freq;

	do
	{
		f_i = 0;
		f_j = 0;
		sum = full_sum;
		for (i = 0;i < h_tree->size_of_end_nodes;i++)
		{
			tmp_i = &(h_tree->end_nodes[i]);
			while (tmp_i->parent != NULL) tmp_i = tmp_i->parent;

			for (j = i + 1;j < h_tree->size_of_end_nodes;j++)
			{
				tmp_j = &(h_tree->end_nodes[j]);
				while (tmp_j->parent != NULL) tmp_j = tmp_j->parent;

				if (tmp_j != tmp_i && sum >= tmp_i->freq + tmp_j->freq)
				{
					sum = tmp_i->freq + tmp_j->freq;
					f_i = i;
					f_j = j;
					f_tmp_i = tmp_i;
					f_tmp_j = tmp_j;
				}
			}
		}
		if (!(f_i == 0 && f_j == 0))
		{
			tmp_node = calloc(1, sizeof(t_bnode));//не забыть освободить память!!!
			tmp_node->freq = sum;
			tmp_node->left_child = f_tmp_i;
			f_tmp_i->parent = tmp_node;
			tmp_node->right_child = f_tmp_j;
			f_tmp_j->parent = tmp_node;
			tmp_node->alpha_index = 0;
			tmp_node->prefix = NULL;
		}
		else break;
	} while (1);

	tmp_prefix = calloc(h_tree->size_of_end_nodes, sizeof(char));
	for (i = 0;i < h_tree->size_of_end_nodes;i++)
	{
		tmp_node = &(h_tree->end_nodes[i]);
		j = 0;
		while (tmp_node->parent)
		{
			if (tmp_node->parent->left_child == tmp_node)  tmp_prefix[j] = '0';
			else tmp_prefix[j] = '1';
			tmp_node = tmp_node->parent;
			j++;
		}
		tmp_prefix[j] = 0;
		reverse(tmp_prefix);
		h_tree->end_nodes[i].prefix = calloc(strlen(tmp_prefix) + 1, sizeof(char)); //не забыть освободить память!!!
		sprintf_s(h_tree->end_nodes[i].prefix, "%s", tmp_prefix);
	}

	free(tmp_prefix);

	return 0;
}

int init_hufftree(char* buf, unsigned int size_of_buf, t_htree* h_tree)
{
	unsigned int tbl[256]; //таблица частот встречаемости символов
	unsigned int i, j;


	h_tree->size_of_end_nodes = 0;

	for (i = 0;i < 256;i++)
		tbl[i] = 0;

	for (i = 0;i < size_of_buf;i++)
		tbl[(unsigned char)(buf[i])]++;

	for (i = 0;i < 256;i++)
		if (tbl[i]) h_tree->size_of_end_nodes++;

	h_tree->end_nodes = calloc(h_tree->size_of_end_nodes, sizeof(t_bnode));

	for (i = 0, j = 0;i < 256;i++)
	{
		if (tbl[i])
		{
			h_tree->end_nodes[j].freq = tbl[i];
			h_tree->end_nodes[j].alpha_index = i;
			h_tree->end_nodes[j].prefix = NULL;
			h_tree->end_nodes[j].parent = NULL;
			h_tree->end_nodes[j].left_child = NULL;
			h_tree->end_nodes[j].right_child = NULL;
			j++;
		}
	}
	complete_hufftree(h_tree);

	return 0;
}

int free_tree(t_bnode* root_node)
{
	if (!root_node->left_child) return 0;

	if (!root_node->left_child->prefix)
		free_tree(root_node->left_child);

	if (!root_node->right_child->prefix)
		free_tree(root_node->right_child);

	free(root_node);

	return 0;
}

int deinit_hufftree(t_htree* tree)
{
	int i;
	t_bnode* root_node;

	if (!tree->size_of_end_nodes) return 0;

	root_node = &(tree->end_nodes[0]);

	while (root_node->parent)
		root_node = root_node->parent;

	free_tree(root_node);

	for (i = 0;i < tree->size_of_end_nodes;i++)
		free(tree->end_nodes[i].prefix);

	free(tree->end_nodes);

	return 0;
}

/*записываем в память buf, начиная с бита с номером seek_b,
последовательность битов, описанную строкой "из нулей и единиц" в hcode*/
int write_bits(char* buf, int seek_b, char* hcode)
{
	int i, n_byte, n_bit, n_bits = strlen(hcode);
	char bit_val, bit_mask;
	char* ptr;

	for (i = 0;i < n_bits;i++) /*перебираем биты к записи, описанные в hcode*/
	{
		bit_val = hcode[i];    		/*значение i-го бита в hcode*/
		n_byte = (seek_b + i) / 8; 		/*номер байта, в который производим запись*/
		ptr = buf + n_byte;      		/*адрес байта, в который производим запись*/
		n_bit = (seek_b + i) % 8; 	    /*номер бита в байте, в который производим запись*/
		bit_mask = 128 >> n_bit;      /*битоавая маска бита в байте, в который производим запись*/

		if (bit_val == '1') ptr[0] |= bit_mask; 		 /*операция записи на случай если бит к записи равен 1*/
		else if (bit_val == '0')  ptr[0] &= (~bit_mask); /*операция записи на случай если бит к записи равен 0*/
	}
	return 0;
}

/*возвращает значение бита с номером seek_b в блоке памяти buf*/
int read_bit(char* buf, int seek_b)
{
	int n_byte, n_bit;
	char* ptr;
	char bit_mask;

	n_byte = seek_b / 8;
	ptr = buf + n_byte;
	n_bit = seek_b % 8;
	bit_mask = 128 >> n_bit;

	if (ptr[0] & bit_mask) return 1;
	else 				return 0;

	return -1;
}


int huffman_code(int in_file, int out_file)
{
	char* buf = NULL;
	char* buf_x = NULL;
	unsigned int n_bits, c_bits, n_bytes, i, j, size_of_buf;
	t_htree tree;
	FILE* fStream;

	fStream = _fdopen(in_file, "rb");
	fseek(fStream, 0, SEEK_END);
	size_of_buf = ftell(fStream);

	buf = calloc(size_of_buf, sizeof(char));
	lseek(in_file, 0, SEEK_SET);
	read(in_file, buf, size_of_buf * sizeof(char));

	init_hufftree(buf, size_of_buf, &tree);
	n_bits = 0;
	for (j = 0;j < size_of_buf;j++)
	{
		for (i = 0;i < tree.size_of_end_nodes;i++)
			if ((unsigned char)buf[j] == tree.end_nodes[i].alpha_index)
				n_bits += strlen(tree.end_nodes[i].prefix);
	}
	n_bytes = n_bits / 8;
	if (n_bits % 8) n_bytes++;
	buf_x = calloc(n_bytes, sizeof(char));
	memset(buf_x, 0, n_bytes);
	c_bits = 0;
	for (j = 0;j < size_of_buf;j++)
	{
		for (i = 0;i < tree.size_of_end_nodes;i++)
			if ((unsigned char)buf[j] == tree.end_nodes[i].alpha_index)
			{
				write_bits(buf_x, c_bits, tree.end_nodes[i].prefix);
				c_bits += strlen(tree.end_nodes[i].prefix);
			}
	}
	free(buf);


	lseek(out_file, 0, SEEK_SET);
	write(out_file, &(tree.size_of_end_nodes), sizeof(unsigned int));
	for (i = 0;i < tree.size_of_end_nodes;i++)
	{
		write(out_file, &(tree.end_nodes[i].freq), sizeof(unsigned int));
		write(out_file, &(tree.end_nodes[i].alpha_index), sizeof(char));
	}
	write(out_file, buf_x, n_bytes);

	free(buf_x);
	deinit_hufftree(&tree);

	return 0;
}

int huffman_decode(int out_file, int decode_file)
{

	char* buf_x = NULL;
	unsigned int n_bits, c_bits, i, size_of_buf;

	t_bnode* root_node;
	t_bnode* cur_node;
	t_htree  tree_in;


	lseek(out_file, 0, SEEK_SET);
	read(out_file, &(tree_in.size_of_end_nodes), sizeof(unsigned int));

	if (!tree_in.size_of_end_nodes) return 0;

	tree_in.end_nodes = (t_bnode*)calloc(tree_in.size_of_end_nodes, sizeof(t_bnode));
	for (i = 0;i < tree_in.size_of_end_nodes;i++)
	{
		read(out_file, &(tree_in.end_nodes[i].freq), sizeof(unsigned int));
		read(out_file, &(tree_in.end_nodes[i].alpha_index), sizeof(char));
		tree_in.end_nodes[i].prefix = NULL;
		tree_in.end_nodes[i].parent = NULL;
		tree_in.end_nodes[i].left_child = NULL;
		tree_in.end_nodes[i].right_child = NULL;
	}
	complete_hufftree(&tree_in);
	n_bits = 0;
	for (i = 0;i < tree_in.size_of_end_nodes;i++)
		n_bits += tree_in.end_nodes[i].freq * strlen(tree_in.end_nodes[i].prefix);
	size_of_buf = n_bits / 8;
	if (n_bits % 8) size_of_buf++;
	buf_x = (char*)calloc(size_of_buf, sizeof(char));
	read(out_file, buf_x, size_of_buf * sizeof(char));

	lseek(decode_file, 0, SEEK_SET);
	root_node = &(tree_in.end_nodes[0]);
	while (root_node->parent)
		root_node = root_node->parent;

	c_bits = 0;
	while (c_bits < n_bits)
	{
		cur_node = root_node;
		while (cur_node->left_child)
		{
			if (read_bit(buf_x, c_bits++)) cur_node = cur_node->right_child;
			else cur_node = cur_node->left_child;
		}
		write(decode_file, &(cur_node->alpha_index), sizeof(char));
	}

	deinit_hufftree(&tree_in);
	free(buf_x);
	return 0;
}
