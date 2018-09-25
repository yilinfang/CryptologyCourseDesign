#pragma once
#include<stdio.h>
#include<stdlib.h>
#include<openssl/md5.h>

const int chainLength = 10000;
const int round = 1000000;
const int len = 36;
const int maxsize = 6;

class rainbow
{
public:
	rainbow();
	~rainbow();
	void CreateRainbowTable(const char* filepath);
	void LoadRainbowTable(const char* filepath);
	unsigned char* Hack(unsigned char* plain);
	unsigned char (*head)[7];
	unsigned char (*tail)[7];
	unsigned char PASSCHAR[37] = "0123456789abcdefghijklmnopqrstuvwxyz";
private:
	void R7(unsigned char* pwd, unsigned char* hash, int step);
	void CopyChar(unsigned char* input, unsigned char* output, int length);
	bool Verify(int index, unsigned char* hash, unsigned char * breaker, int N);
	bool Compare(unsigned char* a, unsigned char* b, int len);
	int Match(unsigned char * p);
};

