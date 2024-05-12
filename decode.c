#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ioctl.h>

#define LINUX 1
#define MAX_LINE_LENGTH 1024

//bringing it alllllll in, for me to decide later.

#include "pel.h"
#include "aes.h"
#include "sha1.h"
#include "decode.h"

unsigned char buffer_d[BUFSIZE + 16 + 20];

// Convert hex char to integer
int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

// Convert a hex string to raw byte array
void hex_string_to_byte_array(const char *hex_string, unsigned char *byte_array, int byte_array_size) {
    for (size_t i = 0; i < sizeof byte_array_size; i++){
        byte_array[i] = '\0';
    }
    int length = strlen(hex_string);
    for (int i = 0; i < length && i / 2 < byte_array_size; i += 2) {
        byte_array[i / 2] = (hex_char_to_int(hex_string[i]) << 4) + hex_char_to_int(hex_string[i + 1]);
    }
}

// Function that would handle the byte array (e.g., decryption)
void process_data(unsigned char *data, int data_len, bool cut) {
    // Example function that just prints the data
    if(!cut){
        printf("Data received (hex): ");
    }
    
    for (int i = 0; i < data_len; i++) {
        if(cut && i<2){
            continue;
        } else if (cut){
            printf("%c", data[i]);
        } else
        {
            printf("%02x", data[i]);
        }
    }
    printf("\n");

    // Add decryption or other data handling logic here
}
//completely validated
void setIVs(unsigned char *byte_array){
    memcpy( IV1, &byte_array[20], 20 );
    printf("%s","IV2:");
    process_data(IV1, 20, false);
    memcpy( IV2, &byte_array[ 0], 20 );
    printf("%s","IV2:");
    process_data(IV2, 20, false);
    pel_setup_context( &send_d_ctx, secret, IV1 );
    pel_setup_context( &recv_d_ctx, secret, IV2 );
}

//this program is INCREDIBLY PICKY with its function sigs
int pel_recv_msg_d( unsigned char buffer[BUFSIZE + 16 + 20], unsigned char *data, int *len ){
    unsigned char temp[16];
    unsigned char hmac[20];
    unsigned char digest[20];
    struct sha1_context sha1_ctx;
    int i, j, ret, blk_len;
    

    //pulls in 16 bytes


    memcpy( temp, data, 16 );

    aes_decrypt( &recv_d_ctx.SK, data );

    for( j = 0; j < 16; j++ )
    {
        data[j] ^= recv_d_ctx.LCT[j];
    }

    *len = ( ((int) data[0]) << 8 ) + (int) data[1];

    memcpy( data, temp, 16 );

    if( *len <= 0 || *len > BUFSIZE )
    {
        pel_errno = PEL_BAD_MSG_LENGTH;

        
        puts("out of range msg according to buffsize");
        exit( 666 );
    }

    blk_len = 2 + *len;

    if( ( blk_len & 0x0F ) != 0 )
    {
        blk_len += 16 - ( blk_len & 0x0F );
    }

    //pulls in next block of data, from pos 16 onwards

    memcpy( hmac, &data[blk_len], 20 );

    /* verify the ciphertext integrity */

    data[blk_len    ] = ( recv_d_ctx.p_cntr << 24 ) & 0xFF;
    data[blk_len + 1] = ( recv_d_ctx.p_cntr << 16 ) & 0xFF;
    data[blk_len + 2] = ( recv_d_ctx.p_cntr <<  8 ) & 0xFF;
    data[blk_len + 3] = ( recv_d_ctx.p_cntr       ) & 0xFF;

    sha1_starts( &sha1_ctx );
    sha1_update( &sha1_ctx, recv_d_ctx.k_ipad, 64 );
    sha1_update( &sha1_ctx, data, blk_len + 4 );
    sha1_finish( &sha1_ctx, digest );

    sha1_starts( &sha1_ctx );
    sha1_update( &sha1_ctx, recv_d_ctx.k_opad, 64 );
    sha1_update( &sha1_ctx, digest, 20 );
    sha1_finish( &sha1_ctx, digest );

    if( memcmp( hmac, digest, 19 ) != 0 )
    {
        pel_errno = PEL_CORRUPTED_DATA;

        puts("corruped block according to hmac");
        exit(666);
    }
    /* increment the packet counter */

    recv_d_ctx.p_cntr++;

    /* finally, decrypt and copy the message */

    for( i = 0; i < blk_len; i += 16 )
    {
        memcpy( temp, &data[i], 16 );

        aes_decrypt( &recv_d_ctx.SK, &data[i] );

        for( j = 0; j < 16; j++ )
        {
            data[i + j] ^= recv_d_ctx.LCT[j];
        }

        memcpy( recv_d_ctx.LCT, temp, 16 );
    }
    //memcpy( data, &buffer[2], *len );

    pel_errno = PEL_UNDEFINED_ERROR;

    return( PEL_SUCCESS );
}

//this program is INCREDIBLY PICKY with its function sigs
int pel_recv_msg_d_send( unsigned char buffer[BUFSIZE + 16 + 20], unsigned char *data, int *len ){
    unsigned char temp[16];
    unsigned char hmac[20];
    unsigned char digest[20];
    struct sha1_context sha1_ctx;
    int i, j, ret, blk_len;
    

    //pulls in 16 bytes


    memcpy( temp, data, 16 );

    aes_decrypt( &send_d_ctx.SK, data );

    for( j = 0; j < 16; j++ )
    {
        data[j] ^= send_d_ctx.LCT[j];
    }

    *len = ( ((int) data[0]) << 8 ) + (int) data[1];

    memcpy( data, temp, 16 );

    if( *len <= 0 || *len > BUFSIZE )
    {
        pel_errno = PEL_BAD_MSG_LENGTH;

        
        puts("out of range msg according to buffsize");
        exit( 666 );
    }

    blk_len = 2 + *len;

    if( ( blk_len & 0x0F ) != 0 )
    {
        blk_len += 16 - ( blk_len & 0x0F );
    }

    //pulls in next block of data, from pos 16 onwards

    memcpy( hmac, &data[blk_len], 20 );

    /* verify the ciphertext integrity */

    data[blk_len    ] = ( send_d_ctx.p_cntr << 24 ) & 0xFF;
    data[blk_len + 1] = ( send_d_ctx.p_cntr << 16 ) & 0xFF;
    data[blk_len + 2] = ( send_d_ctx.p_cntr <<  8 ) & 0xFF;
    data[blk_len + 3] = ( send_d_ctx.p_cntr       ) & 0xFF;

    sha1_starts( &sha1_ctx );
    sha1_update( &sha1_ctx, send_d_ctx.k_ipad, 64 );
    sha1_update( &sha1_ctx, data, blk_len + 4 );
    sha1_finish( &sha1_ctx, digest );

    sha1_starts( &sha1_ctx );
    sha1_update( &sha1_ctx, send_d_ctx.k_opad, 64 );
    sha1_update( &sha1_ctx, digest, 20 );
    sha1_finish( &sha1_ctx, digest );

    if( memcmp( hmac, digest, 19 ) != 0 )
    {
        pel_errno = PEL_CORRUPTED_DATA;

        puts("corruped block according to hmac");
        exit(666);
    }
    /* increment the packet counter */

    send_d_ctx.p_cntr++;

    /* finally, decrypt and copy the message */

    for( i = 0; i < blk_len; i += 16 )
    {
        memcpy( temp, &data[i], 16 );

        aes_decrypt( &send_d_ctx.SK, &data[i] );

        for( j = 0; j < 16; j++ )
        {
            data[i + j] ^= send_d_ctx.LCT[j];
        }

        memcpy( send_d_ctx.LCT, temp, 16 );
    }
    //memcpy( data, &buffer[2], *len );

    pel_errno = PEL_UNDEFINED_ERROR;

    return( PEL_SUCCESS );
}


void process_file(const char* filename, const char* filename2) {
    FILE *file = fopen(filename, "r");
    FILE *file2 = fopen(filename2, "r");
    char line[MAX_LINE_LENGTH];
    unsigned char data[MAX_LINE_LENGTH / 2];
    char line2[MAX_LINE_LENGTH];
    unsigned char data2[MAX_LINE_LENGTH / 2];  // Each byte is represented by two hex characters
    bool ivset = false;
    bool chal = false;
    bool tsh_cmd = false;
    bool runshell = false;

    bool shell_term = false;
    bool shell_winsize = false;

    bool get_file = false;
    bool put_file = false;

    bool skipsend = false;
        
    bool chal_server = true;

    struct winsize ws;

    //ripped from pel_server_init
    int len, len2, frame1;

    //main processing
    //each line is processed here.
    while (fgets(line, sizeof(line), file)) {
        
        int line_length = strlen(line);
        if (line[line_length - 1] == '\n') {
            line[line_length - 1] = '\0';  // Remove newline character
            line_length--;
        }
        hex_string_to_byte_array(line, data, sizeof(data));


        //split first line into IVs, then process IVs appropriately
        //then, next line
        if(!ivset){
            ivset = true;
            setIVs(data);
            continue;
        }
        if(!skipsend){
            fgets(line2, sizeof(line2), file2);
            int line2_length = strlen(line);
            if (line2[line2_length - 1] == '\n') {
                line2[line2_length - 1] = '\0';  // Remove newline character
                line2_length--;
            }
            hex_string_to_byte_array(line2, data2, sizeof(data2));
            pel_recv_msg_d_send( 0, (unsigned char *)&data2, &len2 );
            if(!chal){
                chal_server = memcmp(challenge_d, &data2[1], 16);
            }
            
        } else {
            skipsend = false;
        }
        //printf("input(server):");
        //process_data(data, line_length/2,false);
        pel_recv_msg_d( 0, &data, &len );
        //process_data(data, line_length / 2);
        //the idea is to next recreate pel_recv_msg
        
        if(!chal){
            if(memcmp(challenge_d, &data[1], 16)){
                puts("CHALLENGE PASSED");
                chal = true;
                continue;
            } else {
                puts("Challenge failed");
                exit(666);
            }
        }
        
        if(!tsh_cmd){
            switch(data[2]){
                case RUNSHELL:
                    printf("runshell command recv'd\n");
                    tsh_cmd = true;
                    runshell = true;
                    shell_term = true;
                    skipsend = true;
                    break;
                case PUT_FILE:
                    printf("PUT_FILE command recv'd\n");
                    tsh_cmd = true;
                    break;
                case GET_FILE:
                    printf("GET_FILE command recv'd\n");
                    tsh_cmd = true;
                    break;
                default:
                    puts("unknown command");
            }
            continue;
        }
        if(tsh_cmd){
            if(runshell){
                if(shell_term){
                    printf("%s","TERM Environ Var: ");
                    fwrite(&data[1],sizeof(char),len+1,stdout);
                    puts("");
                    shell_term = false;
                    shell_winsize = true;
                    skipsend = true;
                    frame1 = len;
                    //hypothesis, I can advance 1 block at a time.
                    //each block is 36 characters, and they are all on the same line.
                    pel_recv_msg_d( 0, &data[36], &len );
                    ws.ws_row = ( (int) (data+36)[0] << 8 ) + (int) (data+36)[1];
                    ws.ws_col = ( (int) (data+36)[2] << 8 ) + (int) (data+36)[3];
                    printf("Window size: %hu, %hu\n",ws.ws_row,ws.ws_col);
                    //here we go. "exec bash --login"
                    pel_recv_msg_d( 0, &data[36*2], &len );
                    process_data(&data[36*2], line_length/2-36,false);
                    process_data(&data[36*2], len+2,true);
                    exit(1);
                } else if (shell_winsize) {
                    //TODO:
                    printf("%s","window size Environ Var: ");
                    fwrite(&data[1],sizeof(char),len+1,stdout);
                    puts("");
                    shell_winsize = false;
                }
            } else if (get_file){

            } else if (put_file){

            } else {
                puts("You arent supposed to be here");
            }
        }
        printf("Final output(client):");
        process_data(data, len+2,false);
        printf("Final output(server):");
        process_data(data2, len2+2,false);
    }
    
    fclose(file);
    return;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename> <filename2>\n", argv[0]);
        return 1;
    }
    process_file(argv[1],argv[2]);
}

