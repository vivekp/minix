/*	getpwent(), getpwuid(), getpwnam() - password file routines
 *
 *							Author: Kees J. Bot
 *								31 Jan 1994
 */
#define open _open
#define fcntl _fcntl
#define read _read
#define close _close
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>

static char PASSWD[]= "/etc/passwd";	/* The password file. */
static char SHADOW[]= "/etc/shadow";	/* The shadow file. */
static const char *pwfile;		/* Current password file. */
static const char *shfile;		/* Current shadow file. */
static struct passwd entry;		/* Entry to fill and return. */
static int pwfd= -1;			/* Filedescriptor to the file. */
static int shfd= -1;
static char *lineptr = NULL;		/* One line in the passwd file. */
char password[128];			/* Password in the shadow file. */
FILE *fpwd = NULL;			/* Stream of passwd file. */

void __minix_endpwent(void);
int __minix_setpwent(void);
void __minix_setpwfile(const char *);
void __minix_endshent(void);
int __minix_setshent(void);
void __minix_setshfile(const char *);
static int __minix_getline(void);
static char *__minix_get_passwd_from_user(char *); 
struct passwd *__minix_getpwent(void);
struct passwd *__minix_getpwuid(uid_t);
struct passwd *__minix_getpwnam(const char *);


void __minix_endpwent(void)
/* Close the password file. */
{
	if (pwfd >= 0) {
		(void) close(pwfd);
		pwfd= -1;
	}
}

int __minix_setpwent(void)
/* Open the password file. */
{
	if (pwfd >= 0) __minix_endpwent();

	if (pwfile == NULL) pwfile= PASSWD;

	if ((pwfd= open(pwfile, O_RDONLY)) < 0) return -1;
	fpwd = fdopen(pwfd, "r");
	if(fpwd == NULL)
		exit(EXIT_FAILURE);
	(void) fcntl(pwfd, F_SETFD, fcntl(pwfd, F_GETFD) | FD_CLOEXEC);
	return 0;
}

void __minix_setpwfile(const char *file)
/* Prepare for reading an alternate password file. */
{
	__minix_endpwent();
	pwfile= file;
}

void __minix_endshent(void)
/* Close the shadow file. */
{
	if (shfd >= 0) {
		(void) close(shfd);
		shfd= -1;
	}
}

int __minix_setshent(void)
/* Open the shadow file. */
{
	if (shfd >= 0) __minix_endshent();

	if (shfile == NULL) shfile= SHADOW;

	if ((shfd= open(shfile, O_RDONLY)) < 0) return -1;
	(void) fcntl(shfd, F_SETFD, fcntl(shfd, F_GETFD) | FD_CLOEXEC);
	return 0;
}

void __minix_setshfile(const char *file)
/* Prepare for reading an alternate shadow file. */
{
	__minix_endshent();
	shfile= file;
}

static int __minix_getline(void)
/* Get one line from the password file, return 0 if bad or EOF. */
{
	
	size_t n = 0;
	if ((getline(&lineptr, &n, fpwd)) == -1) {
		return 0;
	}

	return 1;
}

static char *__minix_get_passwd_from_user(char *name) 
/* Scan shadow file for username, return the corresponding passwd entry. */
{
	__minix_setshent();
	if(shfd < 0) return NULL;

	FILE *fp;
	fp = fdopen(shfd, "r"); 
	if(fp == NULL)
		exit(EXIT_FAILURE);
	
	/* until a good line is read. */
	for(;;) {
		bzero(password, 128);
		char line[1024];		
		if(fgets(line, (int)sizeof(line), fp) == NULL)
			return NULL;
		
		char username[128];
		int i, j; 
		i = j = 0;
		while(line[i] != ':') {			/* username */
			username[j++] = line[i++];
		}
		username[j] = '\0';

		j = 0;
		i++;
		while(line[i] != ':') {			/* password */
			password[j++] = line[i++];
		}
		password[j] = '\0';

		if(!strcmp(username,name)) {
			if(password == NULL)
				goto fmt;
			return password;
		}
	}
fmt:
	warnx("corrupted shadow file !\n");
	return NULL;
}

struct passwd *__minix_getpwent(void)
/* Read one entry from the password file. */
{
	/* Open the file if not yet open. */
	if (pwfd < 0 && __minix_setpwent() < 0) return NULL;

	/* Until a good line is read. */
	for (;;) {
		if (!__minix_getline()) return NULL;	/* EOF or corrupt. */
		
		int flag = 0x10;			/* flag for old passwd entry. */	
		pw_scan(lineptr, &entry, &flag);	
		if(entry.pw_name != NULL && 
		   (__minix_get_passwd_from_user(entry.pw_name)) != NULL) {
			entry.pw_passwd = strdup(password);
		}
		return &entry;
	
	}
}

struct passwd *__minix_getpwuid(uid_t uid)
/* Return the password file entry belonging to the user-id. */
{
	struct passwd *pw;

	__minix_endpwent();
	while ((pw= __minix_getpwent()) != NULL && pw->pw_uid != uid) {}
	__minix_endpwent();
	return pw;
}

struct passwd *__minix_getpwnam(const char *name)
/* Return the password file entry belonging to the user name. */
{
	struct passwd *pw;

	__minix_endpwent();
	while ((pw= __minix_getpwent()) != NULL && strcmp(pw->pw_name, name) != 0) {}
	__minix_endpwent();
	
	return pw;
}
