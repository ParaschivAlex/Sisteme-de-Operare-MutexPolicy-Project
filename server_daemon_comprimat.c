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
#include <zmq.h>
#include <string.h>
#include <errno.h>
#define RUNNING_DIR	"/tmp"
#define LOG_FILE "mutex_policy_daemon.log"

struct MUTEX
{
    unsigned int id;
    int deschis;
    int blocat;
    int proces_detinator;
};

struct PID_MUTEX
{
    long pid;
    struct MUTEX mtx;
};

struct PID_MUTEX mtx_atrib[10]; //atribuirea mutex cu scopul crearii acestora fiind un nr maxim de 10 mutecsi
long pid_in_asteptare[10][10]; //contine procesele care asteapta lansarea unui mutex; nr maxim de pid-uri in asteptare e 10
int nr_mtx=0;
int nr_pid=0;// numarul mutex-ului si al pid-ului

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
    
    //socket pentru comunicarea cu clientii
    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int rc = zmq_bind (responder, "tcp://*:5555");
    if (rc != 0)
    	return 0;

    while (ttl > 0)
    {
        char buffer [101];
        char delim[] = " ";
        zmq_recv (responder, buffer, 101, 0);
        char *p = strtok(buffer, delim);
        char nume_functie[101];
        strcpy(nume_functie, p);
        printf("\n");
        printf("Apelare: '%s'\n", nume_functie);

        if (strcmp(nume_functie, "mtx_open") == 0)//gestionarea functiei mtx_open
        {
            int poz;
            p = strtok(NULL, delim);
            long pid = atoi(p);
            printf("PID: %ld\n", pid);

            if(nr_mtx==0)//daca nu este nicun mutex
            {
                nr_mtx=1;//cream unul

                struct MUTEX mtx_nou;
                mtx_nou.id= nr_mtx;//id mutex-ului este numarul acestuia
                mtx_nou.deschis = 1;// il deschidem
                mtx_nou.blocat =0; //nu este blocat inca
                mtx_nou.proces_detinator = pid; //procesul care detine mutex-ul ia pid-ul de mai sus

                struct PID_MUTEX pm_nou;
                pm_nou.pid= pid;//procesul e cel de mai sus
                pm_nou.mtx= mtx_nou; //mutex-ul din pereche este intrarea creata mai sus
                
                mtx_atrib[nr_mtx - 1] = pm_nou;
                poz = nr_mtx - 1;

                char trimitere_id[24];//id-ul mutex-ului ce trebuie trimis catre utilizator (este ecal cu nr_mtx)
                sprintf(trimitere_id, "%d", nr_mtx);
                zmq_send(responder, trimitere_id, 24, 0);
            }
            else
            {
                int mtx_disponibil=0;
                for (int i = 0; i < nr_mtx; i++)
                {
                    if (mtx_atrib[i].mtx.deschis == 0)//luam primul mutex care nu este dechis
                    {
                        //mutex-ul a fost inchis si poate fi deschis iar
                        mtx_atrib[i].mtx.deschis = 1;//deschidem mutex-ul pentru pid-ul curent
                        mtx_atrib[i].mtx.blocat = 0;//valoarea de blocare care este implicita
                        mtx_atrib[i].pid = pid;//asociem procesul curent cu mutex-ul
                        mtx_atrib[i].mtx.proces_detinator = pid;//actualizam detinatorul mutex-ului
                        mtx_disponibil = 1;
                        poz = i;

                        //id-ul mutex-ului ce trebuie trimis catre utilizator (este ecal cu i+1)
                        char trimitere_id[24];
                        sprintf(trimitere_id, "%d", i + 1);/*sprintf inseamna String print. In loc sa tipareasca pe consola, stocheaza iesirea
    pe buffer-ul de caractere specificat in sprintf*/
                        zmq_send(responder, trimitere_id, 24, 0);
                        break;
                    }
                }

                if (!mtx_disponibil)//daca toti mutecsii sunt deschisi
                {
                    nr_mtx = nr_mtx +1;// cream unul nou

                    struct MUTEX mtx_nou;
                    mtx_nou.id= nr_mtx;
                    mtx_nou.deschis = 1;
                    mtx_nou.blocat =0;
                    mtx_nou.proces_detinator = pid;

                    struct PID_MUTEX pm_nou;
                    pm_nou.pid= pid;
                    pm_nou.mtx= mtx_nou;

                    mtx_atrib[nr_mtx - 1] = pm_nou;
                    poz = nr_mtx - 1;

                    char trimitere_id[24];//id-ul mutex-ului ce trebuie trimis catre utilizator (este ecal cu nr_mtx)
                    sprintf(trimitere_id, "%d", nr_mtx);
                    zmq_send(responder, trimitere_id, 24, 0);
                }
                
              }  
		
                printf("Generam id-ul mutex-ului: %d\n", mtx_atrib[nr_mtx - 1].mtx.id);
                printf("Deschis: ok\n");
            

            }
            else if (strcmp(nume_functie, "mtx_close") == 0)//gestionarea functiei mtx_close
            {
                p= strtok(NULL, delim);
                int id_mtx = atoi(p);
                printf("Id mutex: %d\n", id_mtx);

                p = strtok(NULL, delim);
                long pid = atoi(p);
                printf("PID: %ld\n", pid);

                // verificam daca mutex-ul este deschis si deblocat inainte de inchidere
                if (mtx_atrib[id_mtx - 1].mtx.blocat == 1 || mtx_atrib[id_mtx - 1].mtx.deschis == 0 || mtx_atrib[id_mtx - 1].mtx.proces_detinator != pid)
                {
                    printf("Inchidere: nu se poate\n");
                    zmq_send(responder, "-1", 10, 0);
                    continue;
                }

                mtx_atrib[id_mtx - 1].mtx.deschis = 0;
                mtx_atrib[id_mtx - 1].mtx.blocat = 0;

                printf("Inchidere: ok\n");
                zmq_send(responder, "0", 10, 0);
            }

            else if (strcmp(nume_functie, "mtx_lock") == 0)//gestionarea functiei mtx_lock
            {
                p = strtok(NULL, delim);
                int id_mtx = atoi(p);
                printf("Id mutex: %d\n", id_mtx);

                p = strtok(NULL, delim);
                long pid = atoi(p);
                printf("PID: %ld\n", pid);

                if (id_mtx <= 0 || id_mtx > 10 || mtx_atrib[id_mtx - 1].mtx.deschis == 0)//conditiile pentru esec
                {
                    printf("Blocare: nu se poate\n");
                    zmq_send(responder, "-1", 10, 0);
                    continue;
                }

                if (mtx_atrib[id_mtx - 1].mtx.blocat == 1)//daca "id_mtx" este blocat, atunci vom adauga "pid" in "pid_in_asteptare"
                {
                    printf("Blocare: in asteptare\n");
                    int lung = pid_in_asteptare[id_mtx - 1][0];
                    pid_in_asteptare[id_mtx - 1][lung + 1] = pid;
                    pid_in_asteptare[id_mtx - 1][0] = lung + 1;
                    zmq_send(responder, "2", 10, 0);
                    continue;
                }
                else
                {
                    printf("Blocare: ok\n");
                    mtx_atrib[id_mtx - 1].mtx.blocat = 1;//blocam mutex-ul
                    mtx_atrib[id_mtx - 1].pid = pid;//atribuim pid cu mutex-ul blocat
                    zmq_send(responder, "0", 10, 0);
                    continue;
                }
            }

            else if (strcmp(nume_functie, "mtx_check") == 0)//gestioneaza mtx_lock
            {
                p = strtok(NULL, delim);
                int id_mtx= atoi(p);
                printf("Id mutex: %d\n", id_mtx);

                p = strtok(NULL, delim);
                long pid = atoi(p);
                printf("PID: %ld\n", pid);

                int asteapta = 0;
                for (int i = 1; i <= pid_in_asteptare[id_mtx- 1][0]; i++)
                {
                    if (pid_in_asteptare[id_mtx- 1][i] == pid) //daca s-a gasit pid-ul in lista de asteptare
                    {
                        asteapta = 1;
                        printf("Verificare blocare: in asteptare\n");
                        zmq_send(responder, "2", 2, 0);
                        break;
                    }
                }

                if (!asteapta)
                {
                    printf("Verificare blocare: ok\n");
                    zmq_send(responder, "0", 2, 0);
                }
            }

            else if (strcmp(nume_functie, "mtx_unlock") == 0)// gestionarea functiei mtx_unlock
            {
                p = strtok(NULL, delim);
                int id_mtx = atoi(p);
                printf("Id mutex: %d\n", id_mtx);

                p = strtok(NULL, delim);
                long pid = atoi(p);
                printf("PID: %ld\n", pid);

                if (mtx_atrib[id_mtx - 1].mtx.blocat == 0 || mtx_atrib[id_mtx - 1].mtx.deschis == 0)//verific daca mutex-ul este deschis si blocat inainte de inchidere
                {
                    printf("Deblocat: nu se poate\n");
                    zmq_send(responder, "-1", 10, 0);
                    continue;
                }

                mtx_atrib[id_mtx - 1].mtx.deschis = 1;//mutex-ul este acum deschis
                mtx_atrib[id_mtx - 1].mtx.blocat = 0;//mutex-ul este acum deblocat
                // => mutex-ul poate fi atribuit altui pid

                if (pid_in_asteptare[id_mtx - 1][0] == 0)//verificam lista de pid-uri care se afla in asteptare de id_mtx-1
		        {
		        	//nu fac nimic
		        }
                
                else{
                    mtx_atrib[id_mtx - 1].pid = pid_in_asteptare[id_mtx - 1][1];//atribui mutex-ul primului pid care asteapta
                    mtx_atrib[id_mtx - 1].mtx.deschis = 1;
                    mtx_atrib[id_mtx - 1].mtx.blocat = 1;

                    for (int i = 2; i <= pid_in_asteptare[id_mtx - 1][0]; i++)//elimin pid-ul din lista de asteptare
                        pid_in_asteptare[id_mtx - 1][i - 1] = pid_in_asteptare[id_mtx - 1][i];

                    pid_in_asteptare[id_mtx - 1][0] -= 1;
                }

                printf("Deblocare: ok\n");
                zmq_send(responder, "0", 10, 0);
            }

            sleep(1);//Do some work
    }

    syslog (LOG_NOTICE, "Daemon incheiat.");
    closelog();

    return EXIT_SUCCESS;
}
