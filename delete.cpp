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
using qrcodegen::QrSegment;


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
	// const char *golden0 = "Golden ratio \xCF\x86 = 1.";
	// const char *golden1 = "6180339887498948482045868343656381177203091798057628621354486227052604628189024497072072041893911374";
	// const char *golden2 = "......";
    const char *golden0 = "qwerty";

const QrCode qr0 = QrCode::encodeText("314159265358979323846264338327950288419716939937510", QrCode::Ecc::LOW);
	printQr(qr0);

}

int main(){
    doSegmentDemo();
    return 0;
}