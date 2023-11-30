/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By:
     1- Hudson Shaeffer
     2- Zane Metz
Submitted on:
     11/15/23

----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void
handleErrors (char *msg)
{
  fprintf (stderr, "%s\n", msg);
  ERR_print_errors_fp (stderr);
  abort ();
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

unsigned
encrypt (uint8_t *pPlainText, unsigned plainText_len, const uint8_t *key,
         const uint8_t *iv, uint8_t *pCipherText)
{
  int status;
  unsigned len = 0, encryptedLen = 0;

  // Create and initialize the context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    {
      handleErrors ("encrypt: failed to create CTX");
    }

  // Initialise the encryption operation.
  status = EVP_EncryptInit_ex (ctx, ALGORITHM (), NULL, key, iv);
  if (status != 1)
    {
      handleErrors ("encrypt: failed to EncryptInit_ex");
    }

  // Call call encrypt update as many times as needed inside a
  // loop to perform regular encryption
  status
      = EVP_EncryptUpdate (ctx, pCipherText, &len, pPlainText, plainText_len);
  if (status != 1)
    {
      handleErrors ("encrypt: failed to EncryptUpdate");
    }
  encryptedLen += len;

  // If addition ciphertext may still be generated,
  // the pCipherText pointer must first be advanced forward
  pCipherText += len;

  // Finalize the encryption
  status = EVP_EncryptFinal_ex (ctx, pCipherText, &len);
  if (status != 1)
    {
      handleErrors ("encrypt: failed to EncryptFinal_ex");
    }
  encryptedLen += len;

  // clean up
  EVP_CIPHER_CTX_free (ctx);

  return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned
decrypt (uint8_t *pCipherText, unsigned cipherText_len, const uint8_t *key,
         const uint8_t *iv, uint8_t *pDecryptedText)
{
  int status;
  unsigned len = 0, decryptedLen = 0;

  // Create and initialize the context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    {
      handleErrors ("decrypt: failed to create CTX");
    }

  // Initialise the encryption operation.
  status = EVP_DecryptInit_ex (ctx, ALGORITHM (), NULL, key, iv);
  if (status != 1)
    {
      handleErrors ("decrypt: failed to DecryptInit_ex");
    }

  // Call call encrypt update as many times as needed inside a
  // loop to perform regular encryption
  status = EVP_DecryptUpdate (ctx, pDecryptedText, &len, pCipherText,
                              cipherText_len);
  if (status != 1)
    {
      handleErrors ("decrypt: failed to DecryptUpdate");
    }
  decryptedLen += len;

  // If addition ciphertext may still be generated,
  // the pCipherText pointer must first be advanced forward
  pCipherText += len;

  // Finalize the encryption
  status = EVP_DecryptFinal_ex (ctx, pDecryptedText, &len);
  if (status != 1)
    {
      handleErrors ("decrypt: failed to DecryptFinal_ex");
    }
  decryptedLen += len;

  // clean up
  EVP_CIPHER_CTX_free (ctx);

  return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************

static unsigned char
    plaintext[PLAINTEXT_LEN_MAX],  // Temporarily store plaintext
    ciphertext[CIPHER_LEN_MAX],    // Temporarily store outcome of encryption
    decryptext[DECRYPTED_LEN_MAX]; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue.
// However, that makes the code non-reentrant for multithreaded application

//-----------------------------------------------------------------------------

int
encryptFile (int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
  int status = -1;
  unsigned len = -1, encryptedLen = 0, readLen = -1;

  // Create and initialize the context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    {
      handleErrors ("encrypt: failed to create CTX");
    }

  // Initialise the encryption operation.
  status = EVP_EncryptInit_ex (ctx, ALGORITHM (), NULL, key, iv);
  if (status != 1)
    {
      handleErrors ("encrypt: failed to EncryptInit_ex");
    }

  // encryption loop
  while (readLen != 0)
    {
      // clear buffers
      memset (plaintext, 0, PLAINTEXT_LEN_MAX);
      memset (ciphertext, 0, CIPHER_LEN_MAX);

      readLen = read (fd_in, plaintext, PLAINTEXT_LEN_MAX);
      status = EVP_EncryptUpdate (ctx, ciphertext, &len, plaintext, readLen);
      if (status != 1)
        {
          handleErrors ("encrypt: failed to EncryptUpdate");
        }
      encryptedLen += len;
      write (fd_out, ciphertext, len);
    }

  // clear buffers
  memset (plaintext, 0, PLAINTEXT_LEN_MAX);
  memset (ciphertext, 0, CIPHER_LEN_MAX);

  // finalize encryption
  status = EVP_EncryptFinal_ex (ctx, ciphertext, &len);
  if (status != 1)
    {
      handleErrors ("encrypt: failed to EncryptFinal_ex");
    }
  encryptedLen += len;
  write (fd_out, ciphertext, len);

  // clean up
  EVP_CIPHER_CTX_free (ctx);

  return encryptedLen;
}

//-----------------------------------------------------------------------------
int
decryptFile (int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
  int status = -1;
  unsigned len = -1, decryptedLen = 0, readLen = -1;

  // Create and initialize the context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    {
      handleErrors ("encrypt: failed to create CTX");
    }

  // Initialise the encryption operation.
  status = EVP_DecryptInit_ex (ctx, ALGORITHM (), NULL, key, iv);
  if (status != 1)
    {
      handleErrors ("decrypt: failed to EncryptInit_ex");
    }

  // decryption loop
  while (readLen != 0)
    {
      // clear buffers
      memset (ciphertext, 0, CIPHER_LEN_MAX);
      memset (decryptext, 0, DECRYPTED_LEN_MAX);

      readLen = read (fd_in, ciphertext, CIPHER_LEN_MAX);
      status = EVP_DecryptUpdate (ctx, decryptext, &len, ciphertext, readLen);
      if (status != 1)
        {
          handleErrors ("decrypt: failed to DecryptUpdate");
        }
      decryptedLen += len;
      write (fd_out, decryptext, len);
    }

  // clear buffers
  memset (ciphertext, 0, CIPHER_LEN_MAX);
  memset (decryptext, 0, DECRYPTED_LEN_MAX);

  // finalize decryption
  status = EVP_DecryptFinal_ex (ctx, decryptext, &len);
  if (status != 1)
    {
      handleErrors ("encrypt: failed to DecryptFinal");
    }
  decryptedLen += len;
  write (fd_out, decryptext, len);

  // clean up
  EVP_CIPHER_CTX_free (ctx);

  return decryptedLen;
}

//***********************************************************************
// pLAB-02
//***********************************************************************

RSA *
getRSAfromFile (char *filename, int public)
{
  // open the binary file whose name is 'filename' for reading
  // Create a new RSA object using RSA_new() ;
  // if( public ) read a public RSA key into 'rsa'.  Use PEM_read_RSA_PUBKEY()
  // else read a private RSA key into 'rsa'. Use PEM_read_RSAPrivateKey()
  // close the binary file 'filename'

  FILE *fp = fopen (filename, "rb");
  if (fp == NULL)
    {
      fprintf (stderr, "getRSAfromFile: Unable to open RSA key file %s \n",
               filename);
      return NULL;
    }

  RSA *rsa = RSA_new ();
  if (public)
    rsa = PEM_read_RSA_PUBKEY (fp, &rsa, NULL, NULL);
  else
    rsa = PEM_read_RSAPrivateKey (fp, &rsa, NULL, NULL);

  fclose (fp);

  return rsa;
}

//***********************************************************************
// PA-02
//***********************************************************************

size_t
fileDigest (int fd_in, int fd_out, uint8_t *digest)
// Read all the incoming data stream from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, write a copy of the incoming data
// stream file to 'fd_out' Returns actual size in bytes of the computed hash
// (a.k.a. digest value)
{
  // Use EVP_MD_CTX_create() to create new hashing context
  EVP_MD_CTX *ctx = EVP_MD_CTX_create ();

  // Initialize the context using EVP_DigestInit() so that it deploys
  // the EVP_sha256() hashing function
  EVP_DigestInit (ctx, EVP_sha256 ());

  int status = -1;
  unsigned digestedLen = 0, readLen = -1;

  while (readLen != 0)
    {
      // clear buffer
      memset (plaintext, 0, PLAINTEXT_LEN_MAX);
      readLen = read (fd_in, plaintext, PLAINTEXT_LEN_MAX);

      // Use EVP_DigestUpdate() to hash the data you read
      status = EVP_DigestUpdate (ctx, plaintext, readLen);
      if (status != 1)
        {
          handleErrors ("encrypt: failed to EncryptUpdate");
        }

      if (fd_out > 0)
        {
          write (fd_out, plaintext, readLen);
        }
    }

  // Finialize the hash calculation using EVP_DigestFinal() directly
  // into the 'digest' array
  EVP_DigestFinal (ctx, digest, &digestedLen);

  // Use EVP_MD_CTX_destroy( ) to clean up the context
  EVP_MD_CTX_destroy (ctx);

  // return the length of the computed digest in bytes
  return digestedLen;
}

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void
exitError (char *errText)
{
  fprintf (stderr, "%s\n", errText);
  exit (-1);
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int
getKeyFromFile (char *keyF, myKey_t *x)
{
  int fd_key;

  fd_key = open (keyF, O_RDONLY);
  if (fd_key == -1)
    {
      fprintf (stderr, "\nCould not open key file '%s'\n", keyF);
      return 0;
    }

  // first, read the symmetric encryption key
  if (SYMMETRIC_KEY_LEN != read (fd_key, x->key, SYMMETRIC_KEY_LEN))
    {
      fprintf (stderr, "\nCould not read key from file '%s'\n", keyF);
      return 0;
    }

  // Next, read the Initialialzation Vector
  if (INITVECTOR_LEN != read (fd_key, x->iv, INITVECTOR_LEN))
    {
      fprintf (stderr, "\nCould not read the IV from file '%s'\n", keyF);
      return 0;
    }

  close (fd_key);

  return 1; //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are unsigned integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1

unsigned
MSG1_new (FILE *log, uint8_t **msg1, const char *IDa, const char *IDb,
          const Nonce_t Na)
{

  //  Check agains any NULL pointers in the arguments
  if (log == NULL || msg1 == NULL || IDa == NULL || IDb == NULL || Na == NULL) {
    exitError("MSG1_new: Invalid parameters passed");
  }

  // strlen + 1 for the string terminator
  unsigned LenA = strlen(IDa) + 1, LenB = strlen(IDb) + 1; 
  unsigned LenMsg1 = LENSIZE + LenA + LENSIZE + LenB + NONCELEN;
  int offset = 0;
  uint8_t *p;

  // Allocate memory for msg1. MUST always check malloc() did not fail
  *msg1 = calloc(1, LenMsg1);
  if (*msg1 == NULL) {
    exitError("MSG1_new: Calloc failed");
  }

  // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
  p = *msg1;
  for (int i = 0; i < LENSIZE; i++) {           // put len IDa
    p[i] = ((uint8_t*) &LenA)[i];
  }
  offset += LENSIZE;

  for (int i = 0; i < LenA; i++) {              // put IDa
    p[i + offset] = ((uint8_t *) IDa)[i];
  }
  offset += LenA;

  for (int i = 0; i < LENSIZE; i++) {           // put len IDb
    p[i + offset] = ((uint8_t*) &LenB)[i];
  }
  offset += LENSIZE;

  for (int i = 0; i < LenB; i++) {              // put IDb
    p[i + offset] = ((uint8_t *) IDb)[i];
  }
  offset += LenB;

  for (int i = 0; i < NONCELEN; i++) {          // put nonce
    p[i + offset] = ((uint8_t *)Na)[i];
  }

  fprintf (
      log,
      "The following new MSG1 ( %u bytes ) has been created by MSG1_new ():\n",
      LenMsg1);
  // BIO_dumpt the completed MSG1 indented 4 spaces to the right
  BIO_dump_indent_fp(log, *msg1, LenMsg1, 4);
  fprintf (log, "\n");

  return LenMsg1;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void
MSG1_receive (FILE *log, int fd, char **IDa, char **IDb, Nonce_t Na)
{

  //  Check agains any NULL pointers in the arguments
  if (log == NULL || IDa == NULL || IDb == NULL || Na == NULL) {
    exitError("MSG1_receive: Invalid parameters passed");
  }

  unsigned LenMsg1 = 0, LenA, LenB;
  // Throughout this function, don't forget to update LenMsg1 as you receive
  // its components

  // Read in the components of Msg1:  L(A)  ||  A   ||  L(B)  ||  B   ||  Na
  // 1) Read Len(ID_A)  from the pipe
  // On failure to read Len(IDa):
  if (read(fd, &LenA, LENSIZE) < 0)
  {
    fprintf (log,
             "Unable to receive all %lu bytes of Len(IDA) "
             "in MSG1_receive() ... EXITING\n",
             LENSIZE);

    fflush (log);
    fclose (log);
    exitError ("Unable to receive all bytes LenA in MSG1_receive()");
  }
  LenMsg1 += LENSIZE;

  // 2) Allocate memory for ID_A
  *IDa = calloc(1, LenA);
  // On failure to allocate memory:
  if (*IDa == NULL)
  {
    fprintf (log,
             "Out of Memory allocating %u bytes for IDA in MSG1_receive() "
             "... EXITING\n",
             LenA);
    fflush (log);
    fclose (log);
    exitError ("Out of Memory allocating IDA in MSG1_receive()");
  }

  // On failure to read ID_A from the pipe
  if (read(fd, *IDa, LenA) < 0)
  {
    fprintf (log,
             "Unable to receive all %u bytes of IDA in MSG1_receive() "
             "... EXITING\n",
             LenA);
    fflush (log);
    fclose (log);
    exitError ("Unable to receive all bytes of IDA in MSG1_receive()");
  }
  LenMsg1 += LenA;

  // 3) Read Len( ID_B )  from the pipe
  // On failure to read Len( ID_B ):
  if (read(fd, &LenB, LENSIZE) < 0)
  {
    fprintf (log,
             "Unable to receive all %lu bytes of Len(IDB) "
             "in MSG1_receive() ... EXITING\n",
             LENSIZE);

    fflush (log);
    fclose (log);
    exitError ("Unable to receive all bytes of LenB in MSG1_receive()");
  }
  LenMsg1 += LENSIZE;

  // 4) Allocate memory for ID_B
  *IDb = calloc(1, LenB);
  // On failure to allocate memory:
  if (*IDb == NULL)
  {
    fprintf (log,
             "Out of Memory allocating %u bytes for IDB in MSG1_receive() "
             "... EXITING\n",
             LenB);
    fflush (log);
    fclose (log);
    exitError ("Out of Memory allocating IDB in MSG1_receive()");
  }

  // On failure to read ID_B from the pipe
  if (read(fd, *IDb, LenB) < 0)
  {
    fprintf (log,
             "Unable to receive all %u bytes of IDB in MSG1_receive() "
             "... EXITING\n",
             LenB);
    fflush (log);
    fclose (log);
    exitError ("Unable to receive all bytes of IDB in MSG1_receive()");
  }
  LenMsg1 += LenB;

  // 5) Read Na
  // On failure to read Na from the pipe
  if (read(fd, Na, NONCELEN) < 0)
  {
    fprintf (log,
             "Unable to receive all %lu bytes of Na "
             "in MSG1_receive() ... EXITING\n",
             NONCELEN);

    fflush (log);
    fclose (log);
    exitError ("Unable to receive all bytes of Na in MSG1_receive()");
  }
  LenMsg1 += NONCELEN;

  fprintf (log,
           "MSG1 ( %u bytes ) has been received"
           " on FD %d by MSG1_receive():\n",
           LenMsg1, fd);
  fflush (log);
}

//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************
