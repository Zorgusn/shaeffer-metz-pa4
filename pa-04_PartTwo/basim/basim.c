/*----------------------------------------------------------------------------
PA-04:  Part Two Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way
Authentication

FILE:   basim.c

Written By:
     1- Zane Metz
         2- Hudson Shaeffer
Submitted on:
     Insert the date of Submission here
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <stdlib.h>
#include <time.h>

#include "../myCrypto.h"

// Generate random nonces for Basim
void
getNonce4Basim (int which, Nonce_t value)
{
  // Normally we generate random nonces using
  // RAND_bytes( (unsigned char *) value , NONCELEN  );
  // However, for grading purpose, we will use fixed values

  switch (which)
    {
    case 1: // the first and Only nonce
      value[0] = 0x66778899;
      break;

    default: // Invalid agrument. Must be either 1 or 2
      fprintf (stderr,
               "\n\nBasim trying to create an Invalid nonce\n exiting\n\n");
      exit (-1);
    }
}

//*************************************
// The Main Loop
//*************************************
int
main (int argc, char *argv[])
{
  int fd_A2B, fd_B2A;
  FILE *log;

  char *developerName = "Code by Zane and Hudson";

  fprintf (stdout, "Starting Basim's     %s\n", developerName);

  if (argc < 3)
    {
      printf ("\nMissing command-line file descriptors: %s <getFr. Amal> "
              "<sendTo Amal>\n\n",
              argv[0]);
      exit (-1);
    }

  fd_A2B = argv[1]; // Read from Amal   File Descriptor
  fd_B2A = argv[2]; // Send to   Amal   File Descriptor

  log = fopen ("basim/logBasim.txt", "w");
  if (!log)
    {
      fprintf (stderr, "Basim's %s. Could not create log file\n",
               developerName);
      exit (-1);
    }

  BANNER (log);
  fprintf (log, "Starting Basim\n");
  BANNER (log);

  fprintf (log, "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n\n", fd_A2B,
           fd_B2A);

  // Get Basim's master keys with the KDC
  myKey_t Kb; // Basim's master key with the KDC

  // Use  getKeyFromFile( "basim/basimKey.bin" , .... ) )
  // On failure, print "\nCould not get Basim's Masker key & IV.\n" to both
  // stderr and the Log file and exit(-1) On success, print "Basim has this
  // Master Ka { key , IV }\n" to the Log file
  if (getKeyFromFile ("basim/basimKey.bin", &Kb) == 0)
    {
      fprintf (log, "\nCould not get Basim's Masker key & IV.\n");
      fflush (log);
      fclose (log);
      exitError ("\nCould not get Basim's Masker key & IV.\n");
    }
  fprintf (log, "Basim has this Master Ka { key , IV }\n");
  // BIO_dump the Key IV indented 4 spaces to the right
  BIO_dump_indent_fp (log, &Kb.key, 32, 4);
  fprintf (log, "\n");
  // BIO_dump the IV indented 4 spaces to the right
  BIO_dump_indent_fp (log, &Kb.iv, 16, 4);
  // Get Basim's pre-created Nonces: Nb
  Nonce_t Nb;
  getNonce4Basim (1, Nb);

  // Use getNonce4Basim () to get Basim's 1st and only nonce into Nb
  fprintf (log, "Basim will use this Nonce:  Nb\n");
  // BIO_dump Nb indented 4 spaces to the righ
  BIO_dump_indent_fp (log, Nb, NONCELEN, 4);
  fprintf (log, "\n");

  fflush (log);

  //*************************************
  // Receive  & Process   Message 3
  //*************************************
  // PA-04 Part Two
  BANNER (log);
  fprintf (log, "         MSG3 Receive\n");
  BANNER (log);
  char *IDa;
  myKey_t Ks;
  Nonce_t Na2;
  MSG3_receive (log, fd_A2B, &Kb, &Ks, &IDa, &Na2);
  fprintf (log, "\nBasim received Message 3 from Amal with the following:\n");
  fprintf (log, "    Ks { Key , IV } (48 Bytes ) is:\n");
  BIO_dump_indent_fp (log, Ks, KEYSIZE, 4);
  fprintf (log, "    IDa = '%s'\n", IDa);
  fprintf (log, "    Na2 ( 4 Bytes ) is:\n");
  BIO_dump_indent_fp (log, Na2, NONCELEN, 4);
  //*************************************
  // Construct & Send    Message 4
  //*************************************
  // PA-04 Part Two
  BANNER (log);
  fprintf (log, "         MSG4 New\n");
  BANNER (log);
  Nonce_t fNa2;
  fNonce (fNa2, Na2);
  uint8_t *msg4;
  fprintf (log, "Basim is sending this f( Na2 ) in MSG4:\n");
  BIO_dump_indent_fp (log, fNa2, NONCELEN, 4);

  fprintf (log, "\nBasim is sending this Nb in MSG4:\n");
  BIO_dump_indent_fp (log, Nb, NONCELEN, 4);

  unsigned msg4Len = MSG4_new (log, &msg4, &Ks, &fNa2, &Nb);
  write(fd_B2A, msg4, msg4Len);
  fprintf ("Basim Sent the above MSG4 to Amal\n\n");
  //*************************************
  // Receive   & Process Message 5
  //*************************************
  // PA-04 Part Two
  BANNER (log);
  fprintf (log, "         MSG5 Receive\n");
  BANNER (log);
  Nonce_t fNb;
  fNonce (fNb, Nb);
  fprintf (log, "Basim is expecting back this f( Nb ) in MSG5:\n");
  BIO_dump_indent_fp (log, fNb, NONCELEN, 4);
  fprintf (log, "\n");
  Nonce_t fNb_amal;
  MSG5_receive(log, fd_A2B, &Ks, &fNb_amal);

  fprintf(log, "\nBasim received Message 5 from Amal with this f( Nb ): >>>> VALID\n");
  BIO_dump_indent_fp (log, fNb_amal, NONCELEN, 4);

  //*************************************
  // Final Clean-Up
  //*************************************

  fprintf (log, "\n\nBasim has terminated normally. Goodbye\n");
  fclose (log);

  return 0;
}
