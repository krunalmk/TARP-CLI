#include<iostream>
#include<stdlib.h>
#include<termios.h>
#include<signal.h>
#include<unistd.h>
#include<string.h>
#include <cstdio>
#include <fstream>
#include <bits/stdc++.h> 
#include <unistd.h>


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
