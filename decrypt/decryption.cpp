
// Advanced encryption Standard 128-bit block size and 128-bit keysize.
// decryption
//decryption  is  the  process  to obtain  the original data  that was encrypted. 

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structure.h"


using namespace std;

// before start the first round we take cipher text and add key(addroundkey) in  decryption.
// first step is AddRKey(addroundkey).
// AddRKey(128-bit block size with 128-bit key).
// addroundkey is same like encryption. every steps will be inverse but only addroundkey is same in decryption.

void AddRKey(unsigned char * state, unsigned char * Rkey) 
{
	for (int i = 0; i < 16; i++) 
        {
		state[i] ^= Rkey[i];
	}
}

// next step is InverseMixColumn
// in this each byte of each column of matrix transformation must  multiply by each row of the state.
// The results of these multiplication are used with XOR to produce a new four bytes for the next  state.  
// InverseMixColumns uses multiply9, multiply11, multiply13, multiply14 look-up tables
// Unmixes the columns by reversing the effect of MixColumns in encryption

void InverseMixColumns(unsigned char * state) 
{
	unsigned char temp[16];

	temp[0] = (unsigned char)multiply14[state[0]] ^ multiply11[state[1]] ^ multiply13[state[2]] ^ multiply9[state[3]];
	temp[1] = (unsigned char)multiply9[state[0]] ^ multiply14[state[1]] ^ multiply11[state[2]] ^ multiply13[state[3]];
	temp[2] = (unsigned char)multiply13[state[0]] ^ multiply9[state[1]] ^ multiply14[state[2]] ^ multiply11[state[3]];
	temp[3] = (unsigned char)multiply11[state[0]] ^ multiply13[state[1]] ^ multiply9[state[2]] ^ multiply14[state[3]];

	temp[4] = (unsigned char)multiply14[state[4]] ^ multiply11[state[5]] ^ multiply13[state[6]] ^ multiply9[state[7]];
	temp[5] = (unsigned char)multiply9[state[4]] ^ multiply14[state[5]] ^ multiply11[state[6]] ^ multiply13[state[7]];
	temp[6] = (unsigned char)multiply13[state[4]] ^ multiply9[state[5]] ^ multiply14[state[6]] ^ multiply11[state[7]];
	temp[7] = (unsigned char)multiply11[state[4]] ^ multiply13[state[5]] ^ multiply9[state[6]] ^ multiply14[state[7]];

	temp[8] = (unsigned char)multiply14[state[8]] ^ multiply11[state[9]] ^ multiply13[state[10]] ^ multiply9[state[11]];
	temp[9] = (unsigned char)multiply9[state[8]] ^ multiply14[state[9]] ^ multiply11[state[10]] ^ multiply13[state[11]];
	temp[10] = (unsigned char)multiply13[state[8]] ^ multiply9[state[9]] ^ multiply14[state[10]] ^ multiply11[state[11]];
	temp[11] = (unsigned char)multiply11[state[8]] ^ multiply13[state[9]] ^ multiply9[state[10]] ^ multiply14[state[11]];

	temp[12] = (unsigned char)multiply14[state[12]] ^ multiply11[state[13]] ^ multiply13[state[14]] ^ multiply9[state[15]];
	temp[13] = (unsigned char)multiply9[state[12]] ^ multiply14[state[13]] ^ multiply11[state[14]] ^ multiply13[state[15]];
	temp[14] = (unsigned char)multiply13[state[12]] ^ multiply9[state[13]] ^ multiply14[state[14]] ^ multiply11[state[15]];
	temp[15] = (unsigned char)multiply11[state[12]] ^ multiply13[state[13]] ^ multiply9[state[14]] ^ multiply14[state[15]];

	for (int i = 0; i < 16; i++) 
        {
		state[i] = temp[i];
	}
}

// next step is InverseSRow(Inverseshiftrow). shift bytes of the state shift After last round plane text will converted into cipher textcyclically to the right in each row.
// first row is remains same does not shift byte.
// in second row only one byte is shifted circular to the right.
// third row shifted two bytes to the right.
// the last or fourth row shifted three bytes to right.
// after this InverseSRow(Inverseshiftrow) the size of new state is remaning 16 bytes but byte position will be change.

void InverseSRow(unsigned char * state)
{
	unsigned char temp[16];

// block cipher for Column 1

	temp[0] = state[0];
	temp[1] = state[13];
	temp[2] = state[10];
	temp[3] = state[7];

// block cipher for Column 2
 
	temp[4] = state[4];
	temp[5] = state[1];
	temp[6] = state[14];
	temp[7] = state[11];

// block cipher for Column 3 

	temp[8] = state[8];
	temp[9] = state[5];
	temp[10] = state[2];
	temp[11] = state[15];

// block cipher for Column 4 

	temp[12] = state[12];
	temp[13] = state[9];
	temp[14] = state[6];
	temp[15] = state[3];

	for (int i = 0; i < 16; i++) 
        {
		state[i] = temp[i];
	}
}

// use 16 byte of inverse sub-byte
// Uses inverse S-box.
/* 
   InvSubBytes step (the inverse of SubBytes) is used, which requires first 
   taking the inverse of the affine transformation and then finding the multiplicative inverse.
*/
void InverseSbyte(unsigned char * state) 
{
	for (int i = 0; i < 16; i++)  
        {
		state[i] = inv_s[state[i]];
	}
}

// this Round() function for first 9 round in dercrytion.
// all round perform on 128 bits block and 128 bit key size. 
// this Round() function used for all last 9 round but 
// in final round not use InverseMixColumn.

void Round(unsigned char * state, unsigned char * key) 
{
	AddRKey(state, key);  
	InverseMixColumns(state);  
	InverseSRow(state);       
	InverseSbyte(state);      
}

// this is only  last round in decryption
//  this function is same as Round() function but not use InverseMixccolumn in this LastRound function

void LastRound(unsigned char * state, unsigned char * key) 
{
	AddRKey(state, key);             
	InverseSRow(state);              
	InverseSbyte(state);             
}

// AES Decryption function
// THe number of round is defined in this Decryption() funvtion
// all the decryption steps in this Decryption() function
 
void Decryption(unsigned char * Encryptedmsg, unsigned char * ExpedKey, unsigned char * Decryptedmsg)
{
// from encrypted message store the first 16 bytes
	unsigned char state[16];

	for (int i = 0; i < 16; i++) 
        {
		state[i] = Encryptedmsg[i];
	}

	LastRound(state, ExpedKey+160);

	int numberOfRounds = 9; // first 9 round

	for (int i = 8; i >= 0; i--) 
        {
		Round(state, ExpedKey + (16 * (i + 1)));
	}

	AddRKey(state, ExpedKey); // Last round

	for (int i = 0; i < 16; i++) 
        {
		Decryptedmsg[i] = state[i];
	}
}

int main() 
{
        cout <<"----------------------------------------------------------------\n";
        cout <<"////////////////////////////////////////////////////////////////\n";
        cout <<"----------------------------------------------------------------\n";
        cout <<"Advanced Encryption Standard(DECRYPTION) Using 128-bit key size\n";
        cout <<"----------------------------------------------------------------\n";
        cout <<"////////////////////////////////////////////////////////////////\n";
        cout <<"----------------------------------------------------------------\n";

	// use message from msg.aes

	string messagestr;
	ifstream file;
	file.open("msg.aes", ios::in | ios::binary);

	if (file.is_open())
	{
		getline(file, messagestr); // The first line of file is the message
		cout << "encrypted message will read from msg.aes\n";
                cout <<"-----------------------------------------------------\n";
		file.close();
	}

	else cout << "cant open file";

	char * message = new char[messagestr.size()+1];

	strcpy(message, messagestr.c_str());

	int n = strlen((const char*)message);

	unsigned char * Encryptedmsg = new unsigned char[n];
	for (int i = 0; i < n; i++) 
        {
		Encryptedmsg[i] = (unsigned char)message[i];
	}

	// Free memory
	delete[] message;

	// Read in the key
	string keystr;
	ifstream keyfile;
	keyfile.open("keyfile", ios::in | ios::binary);

	if (keyfile.is_open())
	{
		getline(keyfile, keystr); // The first line of file should be the key
		cout << "use the same 128-bit key from keyfile for decrypt the encrypted message \n"; 
                cout <<"-----------------------------------------------------\n";
		keyfile.close();
	}

	else cout << "Unable to open file";

	istringstream hex_chars_stream(keystr);
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
	
	int msgLen = strlen((const char *)Encryptedmsg);

	unsigned char * Decryptedmsg = new unsigned char[msgLen];

	for (int i = 0; i < msgLen; i += 16) 
        {
		Decryption(Encryptedmsg + i, ExpedKey, Decryptedmsg + i);
	}

	cout << "Decrypted message in hexadecimal::>>>>>>\n";
	for (int i = 0; i < msgLen; i++) 
        {
		cout << hex << (int)Decryptedmsg[i];
		cout << " ";
	}
	cout <<"\n";
        cout <<"-----------------------------------------------------\n";
	cout << "Here is your Decrypted message::>>>>>> \n";
	for (int i = 0; i < msgLen; i++) 
        {
		cout << Decryptedmsg[i];
	}
	cout <<"\n";

	return 0;
}
