#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

//handle error function from openssl wiki
void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

//encryption function from openssl wiki
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, 
	    unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new()))
	{
		handleErrors();
	}
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	{
		handleErrors();
	}
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	{
		handleErrors();
	}
	ciphertext_len = len;
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
	{
		handleErrors();
	}
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}
int main(int argc, char *argv[])
{
	//file to open key file
	FILE *keyFile;
	//open file from command argument
	keyFile = fopen(argv[2], "r");
	//check if file exists
	if(keyFile == NULL)
	{
		printf("\nFile does not exist\n");
		exit(1);
	}
	//check size of key file as 256 bits
	fseek(keyFile, 0, SEEK_END);
	int keyFileSize = ftell(keyFile) - 1;
	if(keyFileSize != 32)
	{
		printf("\nKey not a valid size\n");
		exit(1);
	}
	//buffer to hold contents of key file
	unsigned char keyBuffer[keyFileSize];
	//set file pointer back to beginning
	rewind(keyFile);
	//check key file as valid hex value
	for(int x = 0; x < keyFileSize; x++)
	{
		unsigned char temp;
		temp = fgetc(keyFile);
		if(!isxdigit(temp))
		{
			printf("\nKey not valid hex value\n");
			exit(1);
		}
		//store values in key buffer
		keyBuffer[x] = temp;
	}
	//start opening IV file
	FILE *ivFile;
	ivFile = fopen(argv[4], "r");
	if(ivFile == NULL)
	{
		//exit if file doesnt exist
		printf("\nFile does not exist");
		exit(1);
	}
	//check size of IV file as 128 bits
	fseek(ivFile, 0, SEEK_END);
	int ivFileSize = ftell(ivFile) - 1;
	if(ivFileSize != 16)
	{
		printf("\nInvalid IV size");
		exit(1);
	}
	//buffer for iv file values
	unsigned char ivBuffer[ivFileSize];
	//set pointer back to beginning
	rewind(ivFile);
	//check if iv is valid hex value
	for(int x = 0; x < ivFileSize; x++)
	{
		unsigned char temp;
		temp = fgetc(ivFile);
		if(!isxdigit(temp))
		{
			printf("\nNot valid hex value");
			exit(1);
		}
		//store values in iv buffer
		ivBuffer[x] = temp;
		//printf("%c", ivBuffer[x]);
	}
	//need to open plain text file to be encrypted
	FILE *plainTextFile;
	plainTextFile = fopen(argv[6], "r");
	//check if file exists
	if(plainTextFile == NULL)
	{
		printf("\nFile does not exist");
		exit(1);
	}
	//get size of plain text file for buffer
	fseek(plainTextFile, 0, SEEK_END);
	int plainTextSize = ftell(plainTextFile) - 1;
	//reset pointer to beginning of file
	rewind(plainTextFile);
        //make buffer to hold plain text
	unsigned char plainTextBuffer[plainTextSize];
	//fill buffer with values from plain text file
	for(int x = 0; x < plainTextSize; x++)
	{
		unsigned char temp;
		temp = fgetc(plainTextFile);
		plainTextBuffer[x] = temp;
		//printf("%c", plainTextBuffer[x]);
	}
	//buffer for the cipher text
	//making 2x size of plain text to assure space
	unsigned char cipherBuffer[plainTextSize * 2];	
	//int for cipher text length as well as encrypt function
	int cipherLength = encrypt(plainTextBuffer, plainTextSize, keyBuffer, 
				ivBuffer, cipherBuffer);
	//printf("\n%d\n", cipherLength);
	//add a NULL terminator to cipher
	cipherBuffer[cipherLength] = '0';
	cipherBuffer[cipherLength+1] = '\0';
	//open file to write cipher text
	FILE *cipherFile;
	cipherFile = fopen(argv[8], "w");
	//fputs(cipherBuffer, cipherFile);
	for(int x = 0; x <= cipherLength; x++)
	{
		fputc(cipherBuffer[x], cipherFile);
	}
	fclose(cipherFile);
	fclose(plainTextFile);
	fclose(ivFile);
	fclose(keyFile);
	return(0);
}
