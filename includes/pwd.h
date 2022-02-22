#ifndef __PWD_H___
#define __PWD_H___
struct passwd {
        char    *pw_name;     /* Nom d'utilisateur       */
        char    *pw_passwd;   /* Mot de passe            */
//        uid_t    pw_uid;      /* ID utilisateur          */
//        gid_t    pw_gid;      /* ID groupe               */
        char    *pw_gecos;    /* Vrai nom                */
        char    *pw_dir;      /* Répertoire de connexion */
        char    *pw_shell;    /* Shell à la connexion    */
};

struct passwd *getpwnam (const char * name);
struct passwd *getpwuid (uid_t uid);
#endif