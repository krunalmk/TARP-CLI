#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sha1.h"

#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
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

// Converts binary data of length=len to base64 characters.
// Length of the resultant string is stored in flen
// (you must pass pointer flen).

static void doSegmentDemo();
static std::string toSvgString(const QrCode &qr, int border);
static void printQr(const QrCode &qr);

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

int byte_to_str(char *buf, uint8_t *input) {
    printf("\n");
    for (int n = 0; n < 20; n++) {
        sprintf(buf + (2 * n), "%02x", input[n]);
    }
    return 40;
}

int generate_qr(wchar_t *buf, char *data) {
    setlocale(LC_ALL, "");
    // The structure to manage the QR code
    QRCode qrcode;
    long long int i = 0;

// Allocate a chunk of memory to store the QR code
    uint8_t qrcodeBytes[qrcode_getBufferSize(7)];
//    wchar_t white[] = L"\u2588\u2588";
    wchar_t white[] = L"##";
    wchar_t new_line[] = L"\n";
    wchar_t black[] = L"  ";

    qrcode_initText(&qrcode, qrcodeBytes, 5, ECC_HIGH, data);
    for (uint8_t x = 0; x < qrcode.size + 2; x++) {
        wcscat(buf, white);
        i += 2;
    }
    wcscat(buf, new_line);
    i += 1;
    for (uint8_t y = 0; y < qrcode.size; y++) {
        wcscat(buf, white);
        i += 2;
        for (uint8_t x = 0; x < qrcode.size; x++) {
            if (qrcode_getModule(&qrcode, x, y)) {
                wcscat(buf, black);
                i += 2;
            } else {
                wcscat(buf, white);
                i += 2;
            }
        }
        wcscat(buf, white);
        i += 2;
        wcscat(buf, new_line);
        i += 1;
    }
    for (uint8_t x = 0; x < qrcode.size + 2; x++) {
        wcscat(buf, white);
        i += 2;
    }
    wcscat(buf, new_line);
}

void initialize(const char* pUsername) {
    struct stat st = {0};
    char dir_path[1000] = "/home/";
    strcat(dir_path, pUsername);
    strcat(dir_path, "/.krunal_experiment/");

    if (stat(dir_path, &st) == -1) {
        mkdir(dir_path, 0777);
    }
}


///* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
    int retval ;
    struct pam_conv *conv ;

    retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ;
    if( retval==PAM_SUCCESS ) {
        retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
    }

    return retval ;
}

void *GetWC(wchar_t *a, char *c)
{
    const size_t cSize = strlen(c)+1;
    wchar_t wc[1000];
    mbstowcs (a, c, 1000);

//    return wc;
}

///* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
//int main() {



struct pam_message msg[1], *pmsg[1];
    struct pam_response *resp;
    int retval;
    /* these guys will be used by converse() */
    char *input1;


    wchar_t output[100000];
    wchar_t output_msg_1[100000] =  L"QR:\n\n";
    char output_chr[1000000];
    char output_msg[1000000];
    char url[1000] = "http://192.168.29.38:8000"; // replace this with IP address of the server computer
    printf("\nurl: %s", url);
    generate_qr(output, url);
    printf("\n%ls", output);
    wcscat(output_msg_1, output);
    wcscat(output_msg_1, L"\n\n\nPress ENTER when you're ready to scan");
    wcstombs(output_chr, output_msg_1, 1000000);

    pmsg[0] = &msg[0] ;
    msg[0].msg_style = PAM_PROMPT_ECHO_ON ;
    msg[0].msg = output_msg ;
    strcat(msg[0].msg, output_chr);
    resp = NULL ;
//    pthread_t thread_id;
//    pthread_create(&thread_id, );
	if( (retval = converse(pamh, 1 , pmsg, &resp))!=PAM_SUCCESS ) {
//    if( (retval = converse(pamh, 1 , pmsg, NULL))!=PAM_SUCCESS ) {
        // if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
        return retval ;
    }





    
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

//    char hmac[2560];
    uint8_t hmac[2560];
    char hmac_b32[1024];
    SHA1Custom(hmac, secret_and_input, strlen(secret_and_input));
//    SHA1Custom(hmac, "abc", 3);
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
        system("/usr/bin/python3 /home/osboxes/Downloads/SaveSSH/src/main_server_flask.py");
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
        return PAM_SUCCESS;
    }

    return PAM_AUTH_ERR;
//	return PAM_AUTH_ERR;
//	return 0;
}


/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
