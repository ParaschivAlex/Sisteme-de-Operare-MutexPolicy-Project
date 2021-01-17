///daemon-ul

///Compilare:	cc -o mutex_policy_daemon mutex_policy_daemon.c
///Rulare:  ./mutex_policy_daemon
///Testarea daemon-ului:	ps -ef | grep mutex_policy_daemon (sau ps -aux on BSD systems)
///Testare log:	tail -f /tmp/mutex_policy_daemon.log
///Testare semnal:	kill -HUP `cat /tmp/mutex_policy_daemon.lock`
///Terminarea procesului:	kill `cat /tmp/mutex_policy_daemon.lock (sau kill pid)
///Citirea syslog:  grep mutex_policy_daemon /var/log/syslog

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#define RUNNING_DIR	"/tmp"
#define LOG_FILE "mutex_policy_daemon.log"

void log_message(filename,message)//toate mesajele sunt inregistrate in fisiere (in fisiere diferite, dupa cum este necesar). Aceasta este functia de inregistrare a probelor
char *filename;
char *message;
{
    FILE *logfile;
    logfile=fopen(filename,"a");
    if(!logfile)
        return;
    fprintf(logfile,"%s\n",message);
    fclose(logfile);
}

void signal_handler(sig)//mai intai construim o functie de manipulare a semnalului si apoi legam semnale la aceasta funcție
int sig;
{
    switch(sig)
    {
    case SIGHUP:
        log_message(LOG_FILE,"hangup signal catched");
        break;
    case SIGTERM:
        log_message(LOG_FILE,"terminate signal catched");
        exit(0);
        break;
    }
}

int daemonize(char *name, char *path, char *infile, char *outfile, char *errfile)
{
    if (!name)
    {
        name = "mutex_policy_daemon";
    }
    if (!path)
    {
        path = "/";
    }

    if (!infile)
    {
        infile = "/dev/null";
    }
    if (!outfile)
    {
        outfile = "/dev/null";
    }
    if (!errfile)
    {
        errfile = "/dev/null";
    }

    pid_t child, session_id;//id_ul procesului si al sesiunii
    child = fork();//inlaturam procesul parinte

    if (child < 0)
    {
        fprintf(stderr, "Eroare la inlaturarea procesului parinte!\n");
        exit(EXIT_FAILURE);
    }
    else if (child > 0)//daca pid-ul este bun putem sa iesim din procesul parinte
    {
        exit(EXIT_SUCCESS);
    }

    session_id = setsid();//child devine liderul sesiunii in caz de succes
    if (session_id < 0)
    {
        fprintf(stderr, "Eroare la a deveni liderul sesiunii!\n");
        exit(EXIT_FAILURE);
    }

    //ignorarea semnalelor
    signal(SIGCHLD, SIG_IGN);//ignorare child
    signal(SIGTSTP, SIG_IGN); //ignorarea semnalelor tty (Comanda tty este utilizata in mod obisnuit pentru a verifica daca mediul de iesire este un terminal.)
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);

    //gestionarea semnalelor
    signal(SIGHUP, signal_handler); //prinderea semnalului de inchidere
    signal(SIGTERM, signal_handler); //prinderea semnalului de terminare

    child = fork();//fork() iarasi

    if (child < 0)
    {
        fprintf(stderr, "Eroare la fork!\n");
        exit(EXIT_FAILURE);
    }

    if (child > 0)//in cazz de succes lasam parintele sa termine
        exit(EXIT_SUCCESS);

    umask(0);//schimbam masca fisierului => setam permisiuni noi pentru fisier

    chdir(path);//schimbam directorul curent cu cel radacina

    int fd;//inchidem toti descriptorii de fisiere
    for (fd = sysconf(_SC_OPEN_MAX); fd > 0; --fd)
    {
        close(fd);
    }

    //redeschid stdin, stdout, stderr
    stdin = fopen(infile, "r");    //fd=0
    stdout = fopen(outfile, "w+"); //fd=1
    stderr = fopen(errfile, "w+"); //fd=2

    //deschidem syslog
    openlog(name, LOG_PID, LOG_DAEMON);

    return (0);
}

int main()
{
    int test;
    int ttl=120;
    int delay = 15;

    if((test = daemonize("exemplu_daemon", RUNNING_DIR, NULL, NULL, NULL) )!= 0)
    {
        fprintf(stderr, "Eroare la daemonize!\n");
        exit(EXIT_FAILURE);
    }

    while (ttl > 0)
    {
        //codul daemon-ului
        syslog (LOG_NOTICE, "Daemon inceput.", ttl);
        sleep (delay);
        ttl -= delay;
    }

    syslog (LOG_NOTICE, "Daemon incheiat.");
    closelog();

    return EXIT_SUCCESS;
}
