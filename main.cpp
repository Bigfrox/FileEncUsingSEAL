#define _CRT_SECURE_NO_WARNINGS
#include "seal/seal.h"
#include "examples.h"
#include <iostream>
#include <fstream>
#include <atlstr.h>


using namespace std;
using namespace seal;


int main() {
	

	EncryptionParameters parms(scheme_type::BFV);

	parms.set_poly_modulus_degree(4096);

	parms.set_coeff_modulus(CoeffModulus::Default(4096));

	parms.set_plain_modulus(1024);

	auto context = SEALContext::Create(parms);

	
	
	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	
	SecretKey secret_key = keygen.secret_key();

	Encryptor encryptor(context, public_key);

	Evaluator evaluator(context);

	Decryptor decryptor(context, secret_key);
	
	unsigned long long data[257];

	for (int i = 0; i < 256; i++) {
		Plaintext plain_x(to_string(i));
		Ciphertext encrypted_x;
		encryptor.encrypt(plain_x, encrypted_x);
		cout << "plaintext " << i << " is encrypted. -> "<< hex << *(encrypted_x.data()) << endl;
		data[i] = *(encrypted_x.data());
	
	}
	
	

	unsigned long long S = data[0x53];
	unsigned long long h = data[0x68];
	unsigned long long e = data[0x65];
	unsigned long long l = data[0x6C];

//	Ciphertext ct_result;
//	evaluator.add(encrypted_x1, encrypted_x2, ct_result);
//	cout << "CipherText added >> 0x" << hex << *(ct_result.data()) << endl;
//	Plaintext decrypt_test;
//	decryptor.decrypt(ct_result, decrypt_test);
//	cout << "decrypted_test(sum) = 0x" << hex << *(decrypt_test.data()) << endl << endl;


	
		

	
	ifstream file_in;
	ofstream file_out;


	unsigned char n1;
	file_in.open("malicious.sample", ios::in | ios::binary);
	file_out.open("seal_out.bin", ios::out | ios::binary);

	while (!file_in.eof()) {


		file_in.read((char*)&n1, sizeof(char));
		
		


		int plain = n1;
		

		
		unsigned long long x = data[plain];
		file_out.write((char*)&x, sizeof(unsigned long long));
		// unsigned ll 은 8바이트니까 읽을때 8바이트로 읽으면 됨.

	}
	file_in.close();
	file_out.close();

	file_in.open("seal_out.bin", ios::in | ios::binary);

	unsigned long long n2[5]; // Shell
	while (!file_in.eof()) {

		file_in.read((char*)&n2[0], sizeof(unsigned long long));
		//cout << n2[0] << endl;
		//cout << "S : " << S << endl;
		
		if (n2[0] == S){
			cout << "[*] `S` is Found!" << endl;

			file_in.read((char*)&n2[1], sizeof(unsigned long long));
			cout << n2[1] << endl;
			cout << h << endl;
			file_in.read((char*)&n2[2], sizeof(unsigned long long));
			cout << n2[2] << endl;
			cout << e << endl;
			file_in.read((char*)&n2[3], sizeof(unsigned long long));
			cout << n2[3] << endl;
			cout << l << endl;
			file_in.read((char*)&n2[4], sizeof(unsigned long long));
			cout << n2[4] << endl;
			if (n2[1] == h && n2[2] == e && n2[3] == l && n2[4] == l) {
				cout << "[*] `Shell` is Found!" << endl;
				break;
			}
			
		}


	}
	file_in.close();


	return 0;


	
}