/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By: 
     1- YOU  MUST   WRITE 
	 2- FULL NAMES  HERE   (or risk losing points )
Submitted on: 
     Insert the date of Submission here
	 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//
//  ALL YOUR  CODE FORM  PREVIOUS PAs  and pLABs

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na
// All Len(*) fields are unsigned integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

unsigned MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments

    unsigned  LenA    = //  number of bytes in IDa ;
    unsigned  LenB    = //  number of bytes in IDb ;
    unsigned  LenMsg1 = //  number of bytes in the completed MSG1 ;;
    unsigned *lenPtr ; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail

    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;
    
	// use the pointer p to traverse through msg1 and fill the successive parts of the msg 

    fprintf( log , "The following new MSG1 ( %u bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    // BIO_dumpt the completed MSG1 indented 4 spaces to the right
    fprintf( log , "\n" ) ;
    
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments

    unsigned LenMsg1 = 0, LenA , lenB ;
	// Throughout this function, don't forget to update LenMsg1 as you receive its components
 
    // Read in the components of Msg1:  L(A)  ||  A   ||  L(B)  ||  B   ||  Na
    // 1) Read Len(ID_A)  from the pipe
    // On failure to read Len(IDa): 
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDA) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenA in MSG1_receive()" );
    }

    
    // 2) Allocate memory for ID_A 
	// On failure to allocate memory:
    {
        fprintf( log , "Out of Memory allocating %u bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

 	// On failure to read ID_A from the pipe
    {
        fprintf( log , "Unable to receive all %u bytes of IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDA in MSG1_receive()" );
    }

    // 3) Read Len( ID_B )  from the pipe
    // On failure to read Len( ID_B ):
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDB) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of LenB in MSG1_receive()" );
    }

    // 4) Allocate memory for ID_B
	// On failure to allocate memory:
    {
        fprintf( log , "Out of Memory allocating %u bytes for IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG1_receive()" );
    }

 	// On failure to read ID_B from the pipe
    {
        fprintf( log , "Unable to receive all %u bytes of IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDB in MSG1_receive()" );
    }
    
    // 5) Read Na
 	// On failure to read Na from the pipe
    {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG1_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG1_receive()" );
    }
 
    fprintf( log , "MSG1 ( %u bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}


//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************

static unsigned char   ciphertext2[ CIPHER_LEN_MAX    ] ; // Temporarily store outcome of encryption

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are unsigned integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

unsigned MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{


    //---------------------------------------------------------------------------------------
    // Construct TktPlain = { Ks  || L(IDa)  || IDa }
    // in the global scratch buffer plaintext[]


    // Use that global array as a scratch buffer for building the plaintext of the ticket
    // Compute its encrypted version in the global scratch buffer ciphertext[]

    // Now, set TktCipher = encrypt( Kb , plaintext );
    // Store the result in the global scratch buffer ciphertext[]

    //---------------------------------------------------------------------------------------
    // Construct the rest of Message 2 then encrypt it using Ka
    // MSG2 plain = {  Ks || L(IDb) || IDb  ||  Na || L(TktCipher) || TktCipher }

    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || L(Na) || Na || lenTktCipher) || TktCipher
    // Reuse that global array plaintext[] as a scratch buffer for building the plaintext of the MSG2

    // Now, encrypt Message 2 using Ka. 
    // Use the global scratch buffer ciphertext2[] to collect the results

    fprintf( log ,"This is the new MSG2 ( %u Bytes ) before Encryption:\n" , ..... );  
    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , .....  );
    BIO_dump_indent_fp ( log , ..... ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    IDb (%u Bytes) is:\n" , ..... );
    BIO_dump_indent_fp ( log , ..... ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Na (%lu Bytes) is:\n" , NONCELEN);
    BIO_dump_indent_fp ( log , (..... ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Encrypted Ticket (%u Bytes) is\n" , ..... );
    BIO_dump_indent_fp ( log , ..... ) ;  fprintf( log , "\n") ; 

    // Copy the encrypted ciphertext to Caller's msg2 buffer.

    fprintf( log , "The following new Encrypted MSG2 ( %u bytes ) has been"
                   " created by MSG2_new():  \n" , LenMsg2 ) ;
    BIO_dump_indent_fp( log , *msg2 , LenMsg2 , 4 ) ;    fprintf( log , "\n" ) ;    

    fflush( log ) ;    
    
    return LenMsg2 ;    

}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , unsigned *lenTktCipher , uint8_t **tktCipher )
{


    fprintf( log ,"MSG2_receive() got the following Encrypted MSG2 ( %u bytes ) Successfully\n" 
                 , .... );


}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

unsigned MSG3_new( FILE *log , uint8_t **msg3 , const unsigned lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{



    fprintf( log , "The following new MSG3 ( %u bytes ) has been created by "
                   "MSG3_new ():\n" , LenMsg3 ) ;
    BIO_dump_indent_fp( log , *msg3 , LenMsg3 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return( LenMsg3 ) ;

}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{



    fprintf( log ,"The following Encrypted TktCipher ( %d bytes ) was received by MSG3_receive()\n" 
                 , ....  );



    fprintf( log ,"Here is the Decrypted Ticket ( %d bytes ) in MSG3_receive():\n" , lenTktPlain ) ;
    BIO_dump_indent_fp( log , decryptext , ..... ) ;   fprintf( log , "\n");
    fflush( log ) ;




}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

unsigned MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{



    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values


    // Now, encrypt MSG4 plaintext using the session key Ks;
    // Use the global scratch buffer ciphertext[] to collect the result. Make sure it fits.

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    *msg4 = malloc( .... ) ;



    
    fprintf( log , "The following new Encrypted MSG4 ( %u bytes ) has been"
                   " created by MSG4_new ():  \n" , LenMsg4 ) ;
    BIO_dump_indent_fp( log , *msg4 , LenMsg4 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    
    

}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{



    fprintf( log ,"The following Encrypted MSG4 ( %u bytes ) was received:\n" , ...  );



}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

unsigned MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{



    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits 


    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.


    // Now allocate a buffer for the caller, and copy the encrypted MSG5 to it
    *msg5 = malloc( ... ) ;


    fprintf( log , "The following new Encrypted MSG5 ( %u bytes ) has been"
                   " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    BIO_dump_indent_fp( log , *msg5 , LenMSG5cipher , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{

    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.


    fprintf( log ,"The following Encrypted MSG5 ( %u bytes ) has been received:\n" , LenMSG5cipher );


    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits


    // Parse MSG5 into its components f( Nb )



}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    // Note that the nonces are store in Big-Endian byte order
    // This affects how you do arithmetice on the noces, e.g. when you add 1
}
