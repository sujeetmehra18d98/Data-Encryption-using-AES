
// Advanced encryption Standard 128-bit block size and 128-bit keysize.
// Encryption.

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structure.h"

using namespace std;
// befor start the first Round we take plane text and add key(addRoundkey) in encryption and decryption.
// process of initial or pre Round in encryption
 // in each Round 128-bits block size and 
 //  128-bit key size is used. AddRkey(AddRoundkey) is an XOR.
 
void AddRkey(unsigned char * state, unsigned char * Rkey) 
{
	for (int i = 0; i < 16; i++) 
        {
		state[i] ^= Rkey[i];
	}
}
 

// first step in each Round is substitution-byte.
// substitution-byte(SByte) are used  16 bytes or 128 bits in each Round.
void SByte(unsigned char * state) 
{
	for (int i = 0; i < 16; i++) 
        {
		state[i] = s[state[i]];
	}
}
// next step is shift rows. shift bytes of the state cyclically to the left in each  row.
// first row is remains same does not shift byte.
// in second row only one byte is shifted circular to the left.
// third row shifted two bytesto the left.
// the last or fourth row shifted three bytes to left.
// after this shift row the size of new state is remaning 16 bytes but byte position will be change.
void SRow(unsigned char * state) 
{
	unsigned char temp[16];
// each column of the output state of the ShiftRows step is composed of bytes from each column of the input state. 
// AES degenerates into four independent block ciphers.

// block cipher for Column 1 

    temp[0] = state[0];
    temp[1] = state[5];
    temp[2] = state[10];
    temp[3] = state[15];
	
// block cipher for Column 2 
	
    temp[4] = state[4];
    temp[5] = state[9];
    temp[6] = state[14];
    temp[7] = state[3];

// block cipher for Column 3 

    temp[8] = state[8];
    temp[9] = state[13];
    temp[10] = state[2];
    temp[11] = state[7];
	
// block cipher for Column 4 

    temp[12] = state[12];
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];

	for (int i = 0; i < 16; i++) 
        {
		state[i] = temp[i];
	}
}
// next step is mixcolumn.
// in this each byte of each row of matrix transformation must  multiply by each column of the state.
// The results of these multiplication are used with XOR to produce a new four bytes for the next  state. 
// MixColumns uses multiply2, multiply3 look-up tables
// shift rows, mix column provide diffusion in the cipher.
 
void MixColumns(unsigned char * state) 
{
	unsigned char temp[16];

	temp[0] = (unsigned char) multiply2[state[0]] ^ multiply3[state[1]] ^ state[2] ^ state[3];
	temp[1] = (unsigned char) state[0] ^ multiply2[state[1]] ^ multiply3[state[2]] ^ state[3];
	temp[2] = (unsigned char) state[0] ^ state[1] ^ multiply2[state[2]] ^ multiply3[state[3]];
	temp[3] = (unsigned char) multiply3[state[0]] ^ state[1] ^ state[2] ^ multiply2[state[3]];

	temp[4] = (unsigned char)multiply2[state[4]] ^ multiply3[state[5]] ^ state[6] ^ state[7];
	temp[5] = (unsigned char)state[4] ^ multiply2[state[5]] ^ multiply3[state[6]] ^ state[7];
	temp[6] = (unsigned char)state[4] ^ state[5] ^ multiply2[state[6]] ^ multiply3[state[7]];
	temp[7] = (unsigned char)multiply3[state[4]] ^ state[5] ^ state[6] ^ multiply2[state[7]];

	temp[8] = (unsigned char)multiply2[state[8]] ^ multiply3[state[9]] ^ state[10] ^ state[11];
	temp[9] = (unsigned char)state[8] ^ multiply2[state[9]] ^ multiply3[state[10]] ^ state[11];
	temp[10] = (unsigned char)state[8] ^ state[9] ^ multiply2[state[10]] ^ multiply3[state[11]];
	temp[11] = (unsigned char)multiply3[state[8]] ^ state[9] ^ state[10] ^ multiply2[state[11]];

	temp[12] = (unsigned char)multiply2[state[12]] ^ multiply3[state[13]] ^ state[14] ^ state[15];
	temp[13] = (unsigned char)state[12] ^ multiply2[state[13]] ^ multiply3[state[14]] ^ state[15];
	temp[14] = (unsigned char)state[12] ^ state[13] ^ multiply2[state[14]] ^ multiply3[state[15]];
	temp[15] = (unsigned char)multiply3[state[12]] ^ state[13] ^ state[14] ^ multiply2[state[15]];

	for (int i = 0; i < 16; i++) 
        {
		state[i] = temp[i];
	}
}

// we are using 128 bit key size so. number of Rounds is 10.
// process of first 9 Rounds is same 
// Each Round operates on 128 bits.
// this steps is for first 9 Rounds.

void Round(unsigned char * state, unsigned char * key) 
{
	SByte(state);
	SRow(state);
	MixColumns(state);
	AddRkey(state, key);
}

// in last or 10 th Round we will not use mixcolumn but other process is same like previous 9 Rounds.

void LastRound(unsigned char * state, unsigned char * key) 
{
	SByte(state);
	SRow(state);
	AddRkey(state, key);
}

// AES encryption function
// confusion and diffusion steps used into one function
 
void Encryption(unsigned char * message, unsigned char * ExpedKey, unsigned char * encryptedmsg) 
{

        // from encrypted message store the first 16 bytes
	unsigned char state[16]; 

	for (int i = 0; i < 16; i++) 
        {
		state[i] = message[i];
	}

	int numberOfRounds = 9; // number of Round for 128 bit key size aes 

	AddRkey(state, ExpedKey); // Initial Round
        // Round 1 to 9 
	for (int i = 0; i < numberOfRounds; i++) 
        {
		Round(state, ExpedKey + (16 * (i+1)));
	}

	LastRound(state, ExpedKey + 160); //final Rounds

	// encrypted message copyed state to buffer
	for (int i = 0; i < 16; i++) 
        {
		encryptedmsg[i] = state[i];
	}
}

int main() 
{

	char message[1024];

        cout <<"----------------------------------------------------------------\n";
        cout <<"////////////////////////////////////////////////////////////////\n";
        cout <<"----------------------------------------------------------------\n";
        cout <<"Advanced Encryption Standard(ENCRYPTION) Using 128-bit key size\n";
        cout <<"----------------------------------------------------------------\n";
        cout <<"////////////////////////////////////////////////////////////////\n";
        cout <<"----------------------------------------------------------------\n";
   
	cout << "Enter the message that you want to encrypt:>>>>\n";
	cin.getline(message, sizeof(message));
        cout <<"-----------------------------------------------------\n";
	cout <<"Your Original message is::>>>>>>>\n"<< message <<"\n";
        cout <<"-----------------------------------------------------\n";

	// Padding message.
	int OriginalLength =strlen((const char *)message);

	int PaddingMsgLength = OriginalLength;

	if ((PaddingMsgLength % 16) != 0) 
        {
		PaddingMsgLength = (PaddingMsgLength / 16 + 1) * 16;
	}

	unsigned char * Paddingmsg = new unsigned char[PaddingMsgLength];
	for (int i = 0; i < PaddingMsgLength; i++) 
       {
		if (i >= OriginalLength) 
                {
			Paddingmsg[i] = 0;
		}
		else 
                {
			Paddingmsg[i] = message[i];
		}
	 }

	unsigned char * encryptedmsg = new unsigned char[PaddingMsgLength];
// keyfile 
	string str;
	ifstream file;
	file.open("keyfile", ios::in | ios::binary);

	if (file.is_open())
	{
		getline(file, str); 
                cout << "use the 128-bit key from keyfile for encrypt the message \n";
                cout <<"-----------------------------------------------------\n";
		file.close();
	}

	else cout << "cant open file";

	istringstream hex_chars_stream(str);
	unsigned char key[16];
	int i = 0;
	unsigned int c;
	while (hex_chars_stream >> hex >> c)
	{
		key[i] = c;
		i++;
	}

	unsigned char ExpedKey[176];

	KeyExpansion(key, ExpedKey);

	for (int i = 0; i < PaddingMsgLength; i += 16) 
        {
		Encryption(Paddingmsg+i, ExpedKey, encryptedmsg+i);
	}

	cout << "Encrypted message in hexadecimal::>>>>>\n";
        
	for (int i = 0; i < PaddingMsgLength; i++) 
        {
		cout << hex << (int) encryptedmsg[i];
		cout << " ";
	}

	cout <<"\n";

	ofstream outfile;
	outfile.open("msg.aes", ios::out | ios::binary);
	if (outfile.is_open())
	{
		outfile << encryptedmsg;
		outfile.close();
                cout <<"-----------------------------------------------------\n";
		cout << "encrypted string is now in msg.aes file in the form of cipher text\n";
                cout <<"-----------------------------------------------------\n";
	}

	else cout << "cant open file";

	delete[] Paddingmsg;
	delete[] encryptedmsg;

	return 0;
}
