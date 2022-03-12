#include<iostream>
#include<stdlib.h>
#include<termios.h>
#include<signal.h>
#include<unistd.h>
#include<string.h>
#include <time.h>
#include <pthread.h>
#include <cstdio>
#include <fstream>
#include <bits/stdc++.h> 
#include <unistd.h>
#include "sha1.h"


#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include "qrcodegen.hpp"
#include <stdint.h>
#include <wchar.h>
#include <locale.h>
#include <sys/stat.h>


using std::uint8_t;
using qrcodegen::QrCode;

using namespace std;

#define MAX_NAME_LEN 60


const static char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// maps A=>0,B=>1..
const static unsigned char unb64[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //10
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //20
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //30
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //40
        0, 0, 0, 62, 0, 0, 0, 63, 52, 53, //50
        54, 55, 56, 57, 58, 59, 60, 61, 0, 0, //60
        0, 0, 0, 0, 0, 0, 1, 2, 3, 4, //70
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, //80
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, //90
        25, 0, 0, 0, 0, 0, 0, 26, 27, 28, //100
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, //110
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, //120
        49, 50, 51, 0, 0, 0, 0, 0, 0, 0, //130
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //140
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //150
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //160
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //170
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //180
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //190
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //200
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //210
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //220
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //230
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //240
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //250
        0, 0, 0, 0, 0, 0,
}; // This array has 256 elements

static void doSegmentDemo();
static std::string toSvgString(const QrCode &qr, int border);
static void printQr(const QrCode &qr);

// Function for making the input in command line invisible
void getch( char *arr) {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    cin.getline( arr, MAX_NAME_LEN);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

// Function to display message whenever user tries to terminate the process using SIGINT or signal interrupt
void sig_handler(int signum){
  printf("Terminal is secured\n");
}

/* Most important requirement of terlocker is this function.
   * For any input received like commands, interrupts, etc. the terminal is not going to execute it.
   * It will respond only when user enters terlocker's password.
   * After entering the password the terminal will function normally.
*/
void lockTerminals_And_UnlockIfUserEntersPassword( char *password){
  char strFromYesNoTxt[5];
  char str[MAX_NAME_LEN];
  fstream YesNoFile("/home/kmk/Terlocker_Pro/YesNo.txt", ios::out | ios::in | ios::trunc);
  YesNoFile << "Yes";
  YesNoFile.close();

  system("clear");
  system("xmodmap -e \'keycode 52 = 0x0000\'");
  
  for(int i=0;; i++){
    getch( str); // Getting inputs like cmd, texts from user
    // Checking each time if YesNo.txt has password set "Yes" or "No"
    fstream File("/home/kmk/Terlocker_Pro/YesNo.txt", ios::out | ios::in);
    File >> strFromYesNoTxt;
    File.close();

    if( strcmp( strFromYesNoTxt, "No") == 0){
      system("clear");
      exit(1);
    }
    cout<<"Enter password to unlock terminal\n";
    doSegmentDemo();

    // Check if entered password matches actual password. If matches then exit from terlocker
    if( strcmp( password, str) == 0){
        fstream YesNoFile("/home/kmk/Terlocker_Pro/YesNo.txt", ios::out | ios::in | ios::trunc);
        YesNoFile << "No";
        YesNoFile.close();
        signal(SIGINT,SIG_DFL);
        system("xmodmap -e \'keycode 52 = 0x7a\'");
        // system("clear");
        exit(1);
    }
  }
}

bool checkForcharZ( char* str){
    for( int i=0; i< strlen(str); i++)
        if( str[i] == 'z' || str[i] == 'Z')
            return true;
    return false;
}

// Returns a string of SVG code for an image depicting the given QR Code, with the given number
// of border modules. The string always uses Unix newlines (\n), regardless of the platform.
static std::string toSvgString(const QrCode &qr, int border) {
	if (border < 0)
		throw std::domain_error("Border must be non-negative");
	if (border > INT_MAX / 2 || border * 2 > INT_MAX - qr.getSize())
		throw std::overflow_error("Border too large");
	
	std::ostringstream sb;
	sb << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	sb << "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n";
	sb << "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 ";
	sb << (qr.getSize() + border * 2) << " " << (qr.getSize() + border * 2) << "\" stroke=\"none\">\n";
	sb << "\t<rect width=\"100%\" height=\"100%\" fill=\"#FFFFFF\"/>\n";
	sb << "\t<path d=\"";
	for (int y = 0; y < qr.getSize(); y++) {
		for (int x = 0; x < qr.getSize(); x++) {
			if (qr.getModule(x, y)) {
				if (x != 0 || y != 0)
					sb << " ";
				sb << "M" << (x + border) << "," << (y + border) << "h1v1h-1z";
			}
		}
	}
	sb << "\" fill=\"#000000\"/>\n";
	sb << "</svg>\n";
	return sb.str();
}


// Prints the given QrCode object to the console.
static void printQr(const QrCode &qr) {
	int border = 4;
	for (int y = -border; y < qr.getSize() + border; y++) {
		for (int x = -border; x < qr.getSize() + border; x++) {
			std::cout << (qr.getModule(x, y) ? "##" : "  ");
		}
		std::cout << std::endl;
	}
	std::cout << std::endl;
}


// Creates QR Codes with manually specified segments for better compactness.
static void doSegmentDemo() {
	// Illustration "golden"
	const char *golden0 = "Golden ratio \xCF\x86 = 1.";
	const char *golden1 = "6180339887498948482045868343656381177203091798057628621354486227052604628189024497072072041893911374";
	const char *golden2 = "......";
	const QrCode qr2 = QrCode::encodeText(
		(std::string(golden0) + golden1 + golden2).c_str(),
		QrCode::Ecc::LOW);
	printQr(qr2);
	
	// std::vector<uint8_t> bytes(golden0, golden0 + std::strlen(golden0));
	// const QrCode qr3 = QrCode::encodeSegments(
	// 	{QrSegment::makeBytes(bytes), QrSegment::makeNumeric(golden1), QrSegment::makeAlphanumeric(golden2)},
	// 	QrCode::Ecc::LOW);
	// printQr(qr3);
}

int main( int args, char *argv[]){
  signal(SIGINT,sig_handler); // Register signal handler
  char str[MAX_NAME_LEN], yesOrNo;
  char * password = (char*)malloc(MAX_NAME_LEN*sizeof( char));
  
  // Storing password in a variable "password"
  fstream File("/home/kmk/Terlocker_Pro/password.txt", ios::out | ios::in);
  File >> str;
  File.close();
  
  strcpy( password, str);
  
  SetPassword:
    if( args > 1){
        // Check if user wants to set new password
      if( strcmp( argv[1], "setpassword") == 0){
        char tpStr[MAX_NAME_LEN];
	      doSegmentDemo();
        cout<<"Enter current password: ";
        cin>> tpStr;
        
        // Compare if user entered current password correctly 
        if( strcmp( tpStr, str) == 0){
          cout<<"Enter password: ";
          cin>> str;
          cout<< "Do you wish to continue (Y/n)\n";
          cin>> yesOrNo;
          if( yesOrNo != 'Y' && yesOrNo != 'y'){
            return -1;
          }
          else{
            if( checkForcharZ( str)){
                cout<<"Password doesn\'t meet the standards"<<endl;
                exit(0);
            }
            
              // Set new password in password.txt
            fstream MyFile("/home/kmk/Terlocker_Pro/password.txt", ios::out | ios::in | ios::trunc);
            MyFile << str;
            cout<<"Password set successfully\n";
            MyFile.close();
            return 1;
          }
        }
        else{ // If current password entered doesn't match with the password stored
          cout<<"Password doesn't match\n";
          return -1;
        }
      }
    }
  
  // If no password is typed again ask the user to repeat the same process for changing the password
  if( strlen( str)  == 0){
    goto SetPassword;
  }
  
  // Run terlocker
  lockTerminals_And_UnlockIfUserEntersPassword( password);
  return 0;
}


void *GetWC(wchar_t *a, char *c)
{
    const size_t cSize = strlen(c)+1;
    wchar_t wc[1000];
    mbstowcs (a, c, 1000);

//    return wc;
}



int base64(const void *binaryData, int len, char *buf) {
    const unsigned char *bin = (const unsigned char *) binaryData;
    char *res;
    int flen;

    int rc = 0; // result counter
    int byteNo; // I need this after the loop

    int modulusLen = len % 3;
    int pad = ((modulusLen & 1) << 1) + ((modulusLen & 2) >> 1); // 2 gives 1 and 1 gives 2, but 0 gives 0.

    flen = 4 * (len + pad) / 3;
    res = (char *) malloc(flen + 1); // and one for the null
    if (!res) {
        puts("ERROR: base64 could not allocate enough memory.");
        puts("I must stop because I could not get enough");
        return 0;
    }

    for (byteNo = 0; byteNo <= len - 3; byteNo += 3) {
        unsigned char BYTE0 = bin[byteNo];
        unsigned char BYTE1 = bin[byteNo + 1];
        unsigned char BYTE2 = bin[byteNo + 2];
        res[rc++] = b64[BYTE0 >> 2];
        res[rc++] = b64[((0x3 & BYTE0) << 4) + (BYTE1 >> 4)];
        res[rc++] = b64[((0x0f & BYTE1) << 2) + (BYTE2 >> 6)];
        res[rc++] = b64[0x3f & BYTE2];
    }

    if (pad == 2) {
        res[rc++] = b64[bin[byteNo] >> 2];
        res[rc++] = b64[(0x3 & bin[byteNo]) << 4];
        res[rc++] = '=';
        res[rc++] = '=';
    } else if (pad == 1) {
        res[rc++] = b64[bin[byteNo] >> 2];
        res[rc++] = b64[((0x3 & bin[byteNo]) << 4) + (bin[byteNo + 1] >> 4)];
        res[rc++] = b64[(0x0f & bin[byteNo + 1]) << 2];
        res[rc++] = '=';
    }

    res[rc] = 0; // NULL TERMINATOR! ;)
    printf("\nALKSMALKJNS: %s", res);
    strcpy(buf, res);
    return flen;
//    return res ;
}

unsigned char *unbase64(const char *ascii, int len, int *flen) {
    const unsigned char *safeAsciiPtr = (const unsigned char *) ascii;
    unsigned char *bin;
    int cb = 0;
    int charNo;
    int pad = 0;

    if (len < 2) { // 2 accesses below would be OOB.
        // catch empty string, return NULL as result.
        puts("ERROR: You passed an invalid base64 string (too short). You get NULL back.");
        *flen = 0;
        return 0;
    }
    if (safeAsciiPtr[len - 1] == '=') ++pad;
    if (safeAsciiPtr[len - 2] == '=') ++pad;

    *flen = 3 * len / 4 - pad;
    bin = (unsigned char *) malloc(*flen);
    if (!bin) {
        puts("ERROR: unbase64 could not allocate enough memory.");
        puts("I must stop because I could not get enough");
        return 0;
    }

    for (charNo = 0; charNo <= len - 4 - pad; charNo += 4) {
        int A = unb64[safeAsciiPtr[charNo]];
        int B = unb64[safeAsciiPtr[charNo + 1]];
        int C = unb64[safeAsciiPtr[charNo + 2]];
        int D = unb64[safeAsciiPtr[charNo + 3]];

        bin[cb++] = (A << 2) | (B >> 4);
        bin[cb++] = (B << 4) | (C >> 2);
        bin[cb++] = (C << 6) | (D);
    }

    if (pad == 1) {
        int A = unb64[safeAsciiPtr[charNo]];
        int B = unb64[safeAsciiPtr[charNo + 1]];
        int C = unb64[safeAsciiPtr[charNo + 2]];

        bin[cb++] = (A << 2) | (B >> 4);
        bin[cb++] = (B << 4) | (C >> 2);
    } else if (pad == 2) {
        int A = unb64[safeAsciiPtr[charNo]];
        int B = unb64[safeAsciiPtr[charNo + 1]];

        bin[cb++] = (A << 2) | (B >> 4);
    }

    return bin;
}

int byte_to_str(char *buf, uint8_t *input) {
    printf("\n");
    for (int n = 0; n < 20; n++) {
        sprintf(buf + (2 * n), "%02x", input[n]);
    }
    return 40;
}

int byte_to_str(char *buf, char *input) {
    printf("\n");
    for (int n = 0; n < 20; n++) {
        sprintf(buf + (2 * n), "%02x", input[n]);
    }
    return 40;
}

long int num_of_digits(long int val) {
    long int count = 0;
    while (val != 0) {
        val /= 10;     // n = n/10
        ++count;
    }
    return count;
}


char *itoa_8digits(char *buf, long int val) {

    long int count = (num_of_digits(val) - 8);

    while (count > 0) {
        val = val / 10;
        count--;
    }

    sprintf(buf, "%ld", val);

    return buf;

}


void generateQRCode_CheckAppResponse(){
//
// Pseudocode https://security.stackexchange.com/questions/35157/how-does-google-authenticator-work
    char original_secret[100] = "1234567890";
    printf("\noriginal_secret: %s", original_secret);

    char secret[1024];
//	int size_of_decode = base32_encode(original_secret, strlen(original_secret), secret, 1024);
    int size_of_decode = base64(original_secret, strlen(original_secret), secret);
    printf("\nsecret: %s", secret);
    printf("\nsize_of_decode: %d", size_of_decode);
//    exit(0);

    long int input = time(NULL) / (30);
    char input_str[32] = {0};
    itoa_8digits(input_str, input);
    printf("\ninput: %ld", input);
    printf("\ninput: %s", input_str);
//    printf("\ninput: %s", itoa_8digits(input));

    char secret_and_input[1056];
    printf("\nsecret: %s", secret);
    strcpy(secret_and_input, secret);
    strcat(secret_and_input, input_str);
    printf("\nsecret: %s", secret);
    printf("\nsecret_and_input: %s", secret_and_input);

    // uint8_t hmac[2560];
    char hmac[2560];
    char hmac_b32[1024];
    SHA1Custom(hmac, secret_and_input, strlen(secret_and_input)); // hmac
    int hmac_b32_size = byte_to_str(hmac_b32, hmac);
    printf("\nhmac_b32_size: %d", hmac_b32_size);
    printf("\nhmac_b32: %s", hmac_b32);

    char secret_and_hmac[1044];
//    memcpy(secret_and_hmac, secret, sizeof secret);
//    memcpy(secret_and_hmac + (sizeof secret) - 1, hmac, sizeof hmac);
    strcpy(secret_and_hmac, secret);      
    strcat(secret_and_hmac, hmac_b32);
    printf("\nsecret111: %ld", strlen(secret));
    printf("\nhmac111: %ld", strlen(hmac_b32));
    printf("\nsecret_and_hmac1111: %ld", secret_and_hmac);

    char hmac2[256];
    char hmac2_b32[1024];
    printf("\nhmac2: %s", hmac2);
    SHA1Custom(hmac2, secret_and_hmac, strlen(secret_and_hmac)); //apply hashing
//    int hmac2_b32_size = base32_encode(hmac2, 256, hmac2_b32, 1024);
    int hmac2_b32_size = byte_to_str(hmac2_b32, hmac2);
    printf("\nhmac2_b32_size: %d", hmac2_b32_size);
    printf("\nhmac2_b32: %s\n", hmac2_b32);
//    printf("\nhmac2: %s", hmac2);

//    int hmac_len = strlen(hmac2);
    printf("hmac_len: %d\n", hmac2_b32_size);

    int offset = ((int) hmac2_b32[hmac2_b32_size - 1] - 4) % strlen(hmac2_b32);
    printf("offset: %d\n", offset);
    char four_bytes[32];
    itoa_8digits(four_bytes, abs((int) hmac2_b32[offset]));
    itoa_8digits(four_bytes + 2, (int) abs((int) hmac2_b32[offset + 1]));
    itoa_8digits(four_bytes + 4, (int) abs((int) hmac2_b32[offset + 2]));
    itoa_8digits(four_bytes + 6, (int) abs((int) hmac2_b32[offset + 3]));
    four_bytes[8] = '\0';
    printf("four_bytes: %s\n", four_bytes);
    wchar_t four_bytes_w[1000];
    GetWC(four_bytes_w, four_bytes);

    char response_str[100];
        system("/usr/bin/python3 /home/kmk/Documents/College study materials/Sem 6/TARP/Terlocker_Pro/main_server_flask.py");
/////
    FILE *file;
    while((file = fopen("code.txt","r")) == NULL)
    {
        
    }
    // file exists
        fscanf(file, "%[^\n]", response_str);
        fclose(file);
        if (remove("code.txt") == 0)
            printf("Deleted successfully");
/////
    if (strcmp(response_str, four_bytes) == 0) {
        cout<<"Hi";
    }
    }