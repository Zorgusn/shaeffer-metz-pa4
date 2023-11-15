/*-------------------------------------------------------------------------------

FILE:   dispatcher.c

Written By:
     1- Dr. Mohamed Aboutabl
     2- Hudson Shaeffer
     3- Zane Metz
Submitted on:
    11/8/23
-------------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "wrappers.h"

#define READ_END 0
#define WRITE_END 1
#define STDIN 0
#define STDOUT 1
//--------------------------------------------------------------------------
int
main (int argc, char *argv[])
{
  pid_t amalPID, basimPID, kdcPID; // PIDs for forking

  int KDC_to_Amal[2];   // KDC to Amal control pipe
  int Amal_to_KDC[2];   // Amal to KDC control pipe
  int Amal_to_Basim[2]; // Amal to Basim control pipe
  int Basim_to_Amal[2]; // Basim to Amal control pipe

  char arg1[20], arg2[20], arg3[20], arg4[20]; // args for later use

  Pipe (Amal_to_KDC);   // create pipe for Amal-to-KDC control
  Pipe (KDC_to_Amal);   // create pipe for KDC-to-Amal control
  Pipe (Amal_to_Basim); // create pipe for Amal-to-Basim control
  Pipe (Basim_to_Amal); // create pipe for Basim-to-Amal control

  printf ("Dispatcher started and created these pipes:\n");
  printf ("\tAmal-to-KDC   pipe: read=%d  write=%d\n", KDC_to_Amal[READ_END],
          KDC_to_Amal[WRITE_END]);
  printf ("\tKDC-to-Amal   pipe: read=%d  write=%d\n", Amal_to_KDC[READ_END],
          Amal_to_KDC[WRITE_END]);
  printf ("\tAmal-to-Basim pipe: read=%d  write=%d\n", Amal_to_Basim[READ_END],
          Amal_to_Basim[WRITE_END]);
  printf ("\tBasim-to_Amal pipe: read=%d  write=%d\n", Basim_to_Amal[READ_END],
          Basim_to_Amal[WRITE_END]);

  // Create both child processes:
  amalPID = Fork ();
  if (amalPID == 0)
    {
      // This is the Amal process.
      // Amal will not use these ends of the pipes, decrement their 'Ref Count'
      close (KDC_to_Amal[WRITE_END]);   // arg1's other end
      close (Amal_to_KDC[READ_END]);    // arg2's other end
      close (Basim_to_Amal[WRITE_END]); // arg3's other end
      close (Amal_to_Basim[READ_END]);  // arg4's other end

      // Prepare the file descriptors as args to Amal
      snprintf (arg1, 20, "%d", KDC_to_Amal[READ_END]);    // arg1 k-to-a read
      snprintf (arg2, 20, "%d", Amal_to_KDC[WRITE_END]);   // arg2 a-to-k write
      snprintf (arg3, 20, "%d", Basim_to_Amal[READ_END]);  // arg3 b-to-a read
      snprintf (arg4, 20, "%d", Amal_to_Basim[WRITE_END]); // arg4 a-to-b write

      // Now, Start Amal
      char *cmnd = "./amal/amal";
      execlp (cmnd, "Amal", arg1, arg2, arg3, arg4, NULL);

      // the above execlp() only returns if an error occurs
      perror ("ERROR starting Amal");
      exit (-1);
    }
  else
    { // This is still the Dispatcher process
      basimPID = Fork ();
      if (basimPID == 0)
        {
          // This is the Basim process
          // Basim will not use these ends of the pipes, decrement their
          // 'count'
          close (Amal_to_Basim[WRITE_END]);
          close (Basim_to_Amal[READ_END]);
          close (KDC_to_Amal[WRITE_END]);
          close (KDC_to_Amal[READ_END]);
          close (Amal_to_KDC[WRITE_END]);
          close (Amal_to_KDC[READ_END]);

          // Prepare the file descriptors as args to Basim
          snprintf (arg1, 20, "%d", Amal_to_Basim[READ_END]);
          snprintf (arg2, 20, "%d", Basim_to_Amal[WRITE_END]);

          char *cmnd = "./basim/basim";
          execlp (cmnd, "Basim", arg1, arg2, NULL);

          // the above execlp() only returns if an error occurs
          perror ("ERROR starting Basim");
          exit (-1);
        }
      else
        {
          kdcPID = fork ();
          if (kdcPID == 0)
            {
              close (Amal_to_Basim[WRITE_END]);
              close (Amal_to_Basim[READ_END]);
              close (Basim_to_Amal[WRITE_END]);
              close (Basim_to_Amal[READ_END]);
              close (Amal_to_KDC[WRITE_END]);
              close (KDC_to_Amal[READ_END]);

              // Prepare the file descriptors as args to KDC
              snprintf (arg1, 20, "%d", Amal_to_KDC[READ_END]);
              snprintf (arg2, 20, "%d", KDC_to_Amal[WRITE_END]);

              char *cmnd = "./kdc/kdc";
              execlp (cmnd, "KDC", arg1, arg2, NULL);

              // the above execlp() only returns if an error occurs
              perror ("ERROR starting KDC");
              exit (-1);
            }
          else
            {
              // This is still the parent Dispatcher  process
              // close all ends of the pipes so that their 'count' is
              // decremented
              close (Amal_to_Basim[WRITE_END]);
              close (Amal_to_Basim[READ_END]);
              close (Basim_to_Amal[WRITE_END]);
              close (Basim_to_Amal[READ_END]);
              close (KDC_to_Amal[WRITE_END]);
              close (KDC_to_Amal[READ_END]);
              close (Amal_to_KDC[WRITE_END]);
              close (Amal_to_KDC[READ_END]);

              printf ("\n\tDispatcher is now waiting for Amal to terminate\n");
              int exitStatus;
              waitpid (amalPID, &exitStatus, 0);
              printf ("\n\tAmal terminated ... ");
              if (WIFEXITED (exitStatus))
                printf (" with status =%d\n", WEXITSTATUS (exitStatus));

              printf (
                  "\n\tDispatcher is now waiting for Basim to terminate\n");
              waitpid (basimPID, &exitStatus, 0);
              printf ("\n\tBasim terminated ... ");
              if (WIFEXITED (exitStatus))
                printf (" with status =%d\n", WEXITSTATUS (exitStatus));

              printf (
                  "\n\tDispatcher is now waiting for the KDC to terminate\n");
              waitpid (kdcPID, &exitStatus, 0);
              printf ("\n\tKDC terminated ... ");
              if (WIFEXITED (exitStatus))
                printf (" with status =%d\n\n", WEXITSTATUS (exitStatus));
            }
        }
    }
}
