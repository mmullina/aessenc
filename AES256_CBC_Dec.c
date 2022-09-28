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
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
	    unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

	if(!(ctx = EVP_CIPHER_CTX_new()))
	{
		handleErrors();
	}
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	{
		handleErrors();
	}
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	{
		handleErrors();
	}
	plaintext_len = len;
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
	{
		handleErrors();
	}
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
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
	//need to open cipher text file to be decrypted
	FILE *cipherFile;
	cipherFile = fopen(argv[6], "r");
	//check if file exists
	if(cipherFile == NULL)
	{
		printf("\nFile does not exist");
		exit(1);
	}
	//get size of cipher text file for buffer
	fseek(cipherFile, 0, SEEK_END);
	int cipherTextSize = ftell(cipherFile) - 1;
	//printf("\nCipher size is %d\n", cipherTextSize);
	//reset pointer to beginning of file
	rewind(cipherFile);
        //make buffer to hold cipher text
	unsigned char cipherTextBuffer[cipherTextSize];
	//fill buffer with values from cipher text file
	for(int x = 0; x < cipherTextSize; x++)
	{
		unsigned char temp;
		temp = fgetc(cipherFile);
		cipherTextBuffer[x] = temp;
		//printf("%c", cipherTextBuffer[x]);
	}
	//buffer for the plain text
	//making 2x size of cipher text to assure space
	unsigned char plainTextBuffer[cipherTextSize * 2];	
	//int for cipher text length as well as encrypt function
	int plainTextLength = decrypt(cipherTextBuffer, cipherTextSize, keyBuffer, 		      		      ivBuffer, plainTextBuffer);
	//add a NULL terminator to cipher
	plainTextBuffer[plainTextLength] = '\0';
	//open file to write cipher text
	FILE *plainTextFile;
	plainTextFile = fopen(argv[8], "w");
	fputs(plainTextBuffer, plainTextFile);
	fclose(cipherFile);
	fclose(plainTextFile);
	fclose(ivFile);
	fclose(keyFile);
	return(0);
}

