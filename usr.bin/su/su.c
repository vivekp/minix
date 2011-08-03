/*	$NetBSD: su.c,v 1.68 2008/07/21 14:19:26 lukem Exp $	*/

/*
 * Copyright (c) 1988 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef lint
__COPYRIGHT("@(#) Copyright (c) 1988\
 The Regents of the University of California.  All rights reserved.");
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)su.c	8.3 (Berkeley) 4/2/94";*/
#else
__RCSID("$NetBSD: su.c,v 1.68 2008/07/21 14:19:26 lukem Exp $");
#endif
#endif /* not lint */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#ifdef SKEY
#include <skey.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <tzfile.h>
#include <unistd.h>
#include <util.h>

#ifdef LOGIN_CAP
#include <login_cap.h>
#endif

#ifdef KERBEROS5
#include <krb5.h>
#endif

#ifdef ALLOW_GROUP_CHANGE
#include "grutil.h"
#endif
#include "suutil.h"

#ifdef KERBEROS5
#define	ARGSTRX	"-Kdflm"
static int kerberos5(char *, const char *, uid_t);
int use_kerberos = 1;
#else
#define	ARGSTRX	"-dflm"
#endif

#ifndef	SU_GROUP
#ifdef __minix
#define	SU_GROUP	"operator"
#else
#define	SU_GROUP	"wheel"
#endif
#endif

#define GROUP_PASSWORD	"Group Password:"

#ifdef LOGIN_CAP
#define ARGSTR	ARGSTRX "c:"
#else
#define ARGSTR ARGSTRX
#endif

void add2env(char **, char *, int);
static int check_ingroup(int, const char *, const char *, int);

int
main(int argc, char **argv)
{
	extern char **environ;
	struct passwd *pwd;
	char *p;
#ifdef BSD4_4
	struct timeval tp;
#endif
	uid_t ruid;
	int asme, ch, asthem, fastlogin, prio, gohome;
	enum { UNSET, YES, NO } iscsh = UNSET;
	const char *user, *shell, *avshell;
	char *username, **np;
	char *userpass, *class;
	char shellbuf[MAXPATHLEN], avshellbuf[MAXPATHLEN];
	time_t pw_warntime = _PASSWORD_WARNDAYS * SECSPERDAY;
#ifdef LOGIN_CAP
	login_cap_t *lc;
#endif
#ifdef ALLOW_GROUP_CHANGE
	char *gname;
#endif

	(void)setprogname(argv[0]);
	asme = asthem = fastlogin = 0;
	gohome = 1;
	shell = class = NULL;
	while ((ch = getopt(argc, argv, ARGSTR)) != -1)
		switch((char)ch) {
#ifdef KERBEROS5
		case 'K':
			use_kerberos = 0;
			break;
#endif
#ifdef LOGIN_CAP
		case 'c':
			class = optarg;
			break;
#endif
		case 'd':
			asme = 0;
			asthem = 1;
			gohome = 0;
			break;
		case 'f':
			fastlogin = 1;
			break;
		case '-':
		case 'l':
			asme = 0;
			asthem = 1;
			break;
		case 'm':
			asme = 1;
			asthem = 0;
			break;
		case '?':
		default:
			(void)fprintf(stderr,
#ifdef ALLOW_GROUP_CHANGE
			    "usage: %s [%s] [login[:group] [shell arguments]]\n",
#else
			    "usage: %s [%s] [login [shell arguments]]\n",
#endif
			    getprogname(), ARGSTR);
			exit(EXIT_FAILURE);
		}
	argv += optind;

	/* Lower the priority so su runs faster */
	errno = 0;
	prio = getpriority(PRIO_PROCESS, 0);
	if (errno)
		prio = 0;
	if (prio > -2)
		(void)setpriority(PRIO_PROCESS, 0, -2);
	openlog("su", 0, LOG_AUTH);

	/* get current login name and shell */
	ruid = getuid();
	username = getlogin();
	if (username == NULL || (pwd = getpwnam(username)) == NULL ||
	    pwd->pw_uid != ruid)
		pwd = getpwuid(ruid);
	if (pwd == NULL)
		errx(EXIT_FAILURE, "who are you?");
	username = estrdup(pwd->pw_name);
	userpass = estrdup(pwd->pw_passwd);

	if (asme) {
		if (pwd->pw_shell && *pwd->pw_shell) {
			(void)estrlcpy(shellbuf, pwd->pw_shell, sizeof(shellbuf));
			shell = shellbuf;
		} else {
			shell = _PATH_BSHELL;
			iscsh = NO;
		}
	}
	/* get target login information, default to root */
	user = *argv ? *argv : "root";
	np = *argv ? argv : argv - 1;

#ifdef ALLOW_GROUP_CHANGE
	if ((p = strchr(user, ':')) != NULL) {
		*p = '\0';
		gname = ++p;
	}
	else
		gname = NULL;

#ifdef ALLOW_EMPTY_USER
	if (user[0] == '\0' && gname != NULL)
		user = username;
#endif
#endif
	if ((pwd = getpwnam(user)) == NULL)
		errx(EXIT_FAILURE, "unknown login `%s'", user);

#ifdef LOGIN_CAP
	/* force the usage of specified class */
	if (class) {
		if (ruid)
			errx(EXIT_FAILURE, "Only root may use -c");

		pwd->pw_class = class;
	}
	if ((lc = login_getclass(pwd->pw_class)) == NULL)
		errx(EXIT_FAILURE, "Unknown class %s\n", pwd->pw_class);

	pw_warntime = (time_t)login_getcaptime(lc, "password-warn",
	    _PASSWORD_WARNDAYS * SECSPERDAY,
	    _PASSWORD_WARNDAYS * SECSPERDAY);
#endif

	if (ruid
#ifdef KERBEROS5
	    && (!use_kerberos || kerberos5(username, user, pwd->pw_uid))
#endif
	    ) {
		char *pass = pwd->pw_passwd;
		int ok = pwd->pw_uid != 0;

#ifdef SU_ROOTAUTH
		/*
		 * Allow those in group rootauth to su to root, by supplying
		 * their own password.
		 */
		if (!ok) {
			if ((ok = check_ingroup(-1, SU_ROOTAUTH, username, 0))) {
				pass = userpass;
				user = username;
			}
		}
#endif
		/*
		 * Only allow those in group SU_GROUP to su to root,
		 * but only if that group has any members.
		 * If SU_GROUP has no members, allow anyone to su root
		 */
		if (!ok)
			ok = check_ingroup(-1, SU_GROUP, username, 1);
		if (!ok)
			errx(EXIT_FAILURE,
	    "you are not listed in the correct secondary group (%s) to su %s.",
					    SU_GROUP, user);
		/* if target requires a password, verify it */
		if (*pass && pwd->pw_uid != ruid) {	/* XXX - OK? */
			p = getpass("Password:");
#ifdef SKEY
			if (strcasecmp(p, "s/key") == 0) {
				if (skey_haskey(user))
					errx(EXIT_FAILURE,
					    "Sorry, you have no s/key.");
				else {
					if (skey_authenticate(user)) {
						goto badlogin;
					}
				}

			} else
#endif
			if (strcmp(pass, crypt(p, pass)) != 0) {
#ifdef SKEY
 badlogin:
#endif
				(void)fprintf(stderr, "Sorry\n");
				syslog(LOG_WARNING,
					"BAD SU %s to %s%s", username,
					pwd->pw_name, ontty());
				exit(EXIT_FAILURE);
			}
		}
	}

	if (asme) {
		/* if asme and non-standard target shell, must be root */
		if (chshell(pwd->pw_shell) == 0 && ruid)
			errx(EXIT_FAILURE, "permission denied (shell).");
	} else if (pwd->pw_shell && *pwd->pw_shell) {
		shell = pwd->pw_shell;
		iscsh = UNSET;
	} else {
		shell = _PATH_BSHELL;
		iscsh = NO;
	}

	if ((p = strrchr(shell, '/')) != NULL)
		avshell = p+1;
	else
		avshell = shell;

	/* if we're forking a csh, we want to slightly muck the args */
	if (iscsh == UNSET)
		iscsh = strstr(avshell, "csh") ? YES : NO;

	/* set permissions */
#ifdef LOGIN_CAP
# ifdef ALLOW_GROUP_CHANGE
	/* if we aren't changing users, keep the current group members */
	if (ruid != pwd->pw_uid &&
	    setusercontext(lc, pwd, pwd->pw_uid, LOGIN_SETGROUP) == -1)
		err(EXIT_FAILURE, "setting user context");

	addgroup(lc, gname, pwd, ruid, GROUP_PASSWORD);

	if (setusercontext(lc, pwd, pwd->pw_uid,
		(u_int)(asthem ? (LOGIN_SETPRIORITY | LOGIN_SETUMASK) : 0) |
		LOGIN_SETRESOURCES | LOGIN_SETUSER) == -1)
		err(EXIT_FAILURE, "setting user context");
# else
	if (setusercontext(lc, pwd, pwd->pw_uid,
		(u_int)(asthem ? (LOGIN_SETPRIORITY | LOGIN_SETUMASK) : 0) |
		LOGIN_SETRESOURCES | LOGIN_SETGROUP | LOGIN_SETUSER) == -1)
		err(EXIT_FAILURE, "setting user context");
# endif
#else
	if (setgid(pwd->pw_gid) == -1)
		err(EXIT_FAILURE, "setgid");
	/* if we aren't changing users, keep the current group members */
	if (ruid != pwd->pw_uid && initgroups(user, pwd->pw_gid) != 0)
		errx(EXIT_FAILURE, "initgroups failed");
# ifdef ALLOW_GROUP_CHANGE
	addgroup(/*EMPTY*/, gname, pwd, ruid, GROUP_PASSWORD);
# endif
	if (setuid(pwd->pw_uid) == -1)
		err(EXIT_FAILURE, "setuid");
#endif

#ifdef __minix
#define EXTRA_ENV 6

	char **env;
	int ap, envsiz;
	char path[1024];
	char usern[32];
	char logname[35];
	char home[128];
	char usershell[128];
	char terminal[128];
	char su_from[128];

	char *bp, *sh, *argx[8], **ep;
	char argx0[64];

	/* Create the argv[] array from the pw_shell field. */
	ap = 0;
	argx[ap++] = argx0;
	if (pwd->pw_shell[0]) {
		sh = pwd->pw_shell;
		bp = sh;
		while (*bp) {
			while (*bp && *bp != ' ' && *bp != '\t') bp++;
			if (*bp == ' ' || *bp == '\t') {
				*bp++ = '\0';	/* mark end of string */
				argx[ap++] = bp;
			}
		}
	} else
	argx[ap] = NULL;
	strcpy(argx0, "-");	/* most shells need it for their .profile */
	if ((bp= strrchr(sh, '/')) == NULL) bp = sh; else bp++;
	strncat(argx0, bp, sizeof(argx0) - 2);

	/* Set the environment */
	if (asme && !asthem) {
		for (ep = environ; *ep; ep++)
			;
	} else
		ep = environ;

	envsiz= ep-environ;
	env= calloc(envsiz + EXTRA_ENV, sizeof(*env));
	if (env == NULL)
	{
		fprintf(stderr, "login: out of memory\n");
		exit(1);
	}
	int i;
	for (i= 0; i<envsiz; i++)
		env[i]= environ[i];

	/* PATH should be set according to the '-m' flag.
	 * This is a temporary hack to set PATH without '-m' flag,
	 * and must be fixed later. 
	 */ 
	strcpy(path, "PATH=");
	strcat(path, _PATH_DEFPATH);
	add2env(env, path, 1);
#endif
	
	if (!asme) {
		if (asthem) {
			p = getenv("TERM");
			/* Create an empty environment */
			environ = emalloc(sizeof(char *));
			environ[0] = NULL;
#ifdef LOGIN_CAP
			if (setusercontext(lc, pwd, pwd->pw_uid,
				LOGIN_SETPATH) == -1)
				err(EXIT_FAILURE, "setting user context");
#else
#ifndef __minix
			(void)setenv("PATH", _PATH_DEFPATH, 1);
#endif /* __minix */
#endif /* LOGIN_CAP */
			if (p)
#ifndef __minix
				(void)setenv("TERM", p, 1);
#else
				strcpy(terminal, "TERM=");
				strcat(terminal, p);
				add2env(env, terminal, 1);
#endif /* __minix */	
			if (gohome && chdir(pwd->pw_dir) == -1)
				errx(EXIT_FAILURE, "no directory");
		}

		if (asthem || pwd->pw_uid) {
#ifndef __minix
			(void)setenv("LOGNAME", pwd->pw_name, 1);
			(void)setenv("USER", pwd->pw_name, 1);
#else
			strcpy(logname, "LOGNAME=");
			strcat(logname, pwd->pw_name);
			add2env(env, logname, 1);
			strcpy(usern, "USER=");
			strcat(usern, pwd->pw_name);
			add2env(env, usern, 1);
#endif /* __minix */	
		}
#ifndef __minix
		(void)setenv("HOME", pwd->pw_dir, 1);
		(void)setenv("SHELL", shell, 1);
#else
		strcpy(home, "HOME=");
		strcat(home, pwd->pw_dir);
		add2env(env, home, 1);
		strcpy(usershell, "SHELL=");
		strcat(usershell, pwd->pw_shell);
		add2env(env, usershell, 1);
#endif
	}
#ifndef __minix
	(void)setenv("SU_FROM", username, 1);
#else
	strcpy(su_from, "SU_FROM=");
	strcat(su_from, username);
	add2env(env, su_from, 1);
#endif
	if (iscsh == YES) {
		if (fastlogin)
			*np-- = __UNCONST("-f");
		if (asme)
			*np-- = __UNCONST("-m");
	} else {
		if (fastlogin)
			(void)unsetenv("ENV");
	}

	if (asthem) {
		avshellbuf[0] = '-';
		(void)estrlcpy(avshellbuf + 1, avshell, sizeof(avshellbuf) - 1);
		avshell = avshellbuf;
	} else if (iscsh == YES) {
		/* csh strips the first character... */
		avshellbuf[0] = '_';
		(void)estrlcpy(avshellbuf + 1, avshell, sizeof(avshellbuf) - 1);
		avshell = avshellbuf;
	}
	*np = __UNCONST(avshell);

#ifdef BSD4_4
	if (pwd->pw_change || pwd->pw_expire)
		(void)gettimeofday(&tp, (struct timezone *)NULL);
	if (pwd->pw_change) {
		if (tp.tv_sec >= pwd->pw_change) {
			(void)printf("%s -- %s's password has expired.\n",
				     (ruid ? "Sorry" : "Note"), user);
			if (ruid != 0)
				exit(EXIT_FAILURE);
		} else if (pwd->pw_change - tp.tv_sec < pw_warntime)
			(void)printf("Warning: %s's password expires on %s",
				     user, ctime(&pwd->pw_change));
	}
	if (pwd->pw_expire) {
		if (tp.tv_sec >= pwd->pw_expire) {
			(void)printf("%s -- %s's account has expired.\n",
				     (ruid ? "Sorry" : "Note"), user);
			if (ruid != 0)
				exit(EXIT_FAILURE);
		} else if (pwd->pw_expire - tp.tv_sec <
		    _PASSWORD_WARNDAYS * SECSPERDAY)
			(void)printf("Warning: %s's account expires on %s",
				     user, ctime(&pwd->pw_expire));
	}
#endif
	if (ruid != 0)
		syslog(LOG_NOTICE, "%s to %s%s",
		    username, pwd->pw_name, ontty());

	/* Raise our priority back to what we had before */
	(void)setpriority(PRIO_PROCESS, 0, prio);

#ifdef __minix
	execve(shell, argx, env);
#else
	(void)execv(shell, np);
#endif
	err(EXIT_FAILURE, "%s", shell);
	/* NOTREACHED */
}


#ifdef KERBEROS5
static int
kerberos5(char *username, const char *user, uid_t uid)
{
	krb5_error_code ret;
	krb5_context context;
	krb5_principal princ = NULL;
	krb5_ccache ccache, ccache2;
	char *cc_name;
	const char *filename;

	ret = krb5_init_context(&context);
	if (ret)
		return 1;

	if (strcmp(user, "root") == 0)
		ret = krb5_make_principal(context, &princ,
					  NULL, username, "root", NULL);
	else
		ret = krb5_make_principal(context, &princ,
					  NULL, user, NULL);
	if (ret)
		goto fail;
	if (!krb5_kuserok(context, princ, user) && !uid) {
		warnx("kerberos5: not in %s's ACL.", user);
		goto fail;
	}
	ret = krb5_cc_gen_new(context, &krb5_mcc_ops, &ccache);
	if (ret)
		goto fail;
	ret = krb5_verify_user_lrealm(context, princ, ccache, NULL, TRUE,
				      NULL);
	if (ret) {
		krb5_cc_destroy(context, ccache);
		switch (ret) {
		case KRB5_LIBOS_PWDINTR :
			break;
		case KRB5KRB_AP_ERR_BAD_INTEGRITY:
		case KRB5KRB_AP_ERR_MODIFIED:
			krb5_warnx(context, "Password incorrect");
			break;
		default :
			krb5_warn(context, ret, "krb5_verify_user");
			break;
		}
		goto fail;
	}
	ret = krb5_cc_gen_new(context, &krb5_fcc_ops, &ccache2);
	if (ret) {
		krb5_cc_destroy(context, ccache);
		goto fail;
	}
	ret = krb5_cc_copy_cache(context, ccache, ccache2);
	if (ret) {
		krb5_cc_destroy(context, ccache);
		krb5_cc_destroy(context, ccache2);
		goto fail;
	}

	filename = krb5_cc_get_name(context, ccache2);
	(void)easprintf(&cc_name, "%s:%s", krb5_cc_get_type(context, ccache2),
		 filename);
	if (chown(filename, uid, NOGROUP) == -1) {
		warn("chown %s", filename);
		free(cc_name);
		krb5_cc_destroy(context, ccache);
		krb5_cc_destroy(context, ccache2);
		goto fail;
	}

	(void)setenv("KRB5CCNAME", cc_name, 1);
	free(cc_name);
	krb5_cc_close(context, ccache2);
	krb5_cc_destroy(context, ccache);
	return 0;

 fail:
	if (princ != NULL)
		krb5_free_principal(context, princ);
	krb5_free_context(context);
	return 1;
}
#endif /* KERBEROS5 */

static int
check_ingroup(int gid, const char *gname, const char *user, int ifempty)
{
	struct group *gr;
	char **g;
#ifdef SU_INDIRECT_GROUP
	char **gr_mem;
	int n = 0;
	int i = 0;
#endif
	int ok = 0;

	if (gname == NULL)
		gr = getgrgid((gid_t) gid);
	else
		gr = getgrnam(gname);

	/*
	 * XXX we are relying on the fact that we only set ifempty when
	 * calling to check for SU_GROUP and that is the only time a
	 * missing group is acceptable.
	 */
	if (gr == NULL)
		return ifempty;
	if (!*gr->gr_mem)		/* empty */
		return ifempty;

	/*
	 * Ok, first see if user is in gr_mem
	 */
	for (g = gr->gr_mem; *g; ++g) {
		if (strcmp(*g, user) == 0)
			return 1;	/* ok */
#ifdef SU_INDIRECT_GROUP
		++n;			/* count them */
#endif
	}
#ifdef SU_INDIRECT_GROUP
	/*
	 * No.
	 * Now we need to duplicate the gr_mem list, and recurse for
	 * each member to see if it is a group, and if so whether user is
	 * in it.
	 */
	gr_mem = emalloc((n + 1) * sizeof (char *));
	for (g = gr->gr_mem, i = 0; *g; ++g) {
		gr_mem[i] = estrdup(*g);
		i++;
	}
	gr_mem[i++] = NULL;

	for (g = gr_mem; ok == 0 && *g; ++g) {
		/*
		 * If we get this far we don't accept empty/missing groups.
		 */
		ok = check_ingroup(-1, *g, user, 0);
	}
	for (g = gr_mem; *g; ++g) {
		free(*g);
	}
	free(gr_mem);
#endif
	return ok;
}

#ifdef __minix
void add2env(char **env, char *entry, int replace)
{
/* Replace an environment variable with entry or add entry if the environment
 * variable doesn't exit yet. 
 */
	char *cp;
	int keylen;

	cp= strchr(entry, '=');
	keylen= cp-entry+1;

	for(; *env; env++)
	{
		if (strncmp(*env, entry, keylen) == 0) {
			if (!replace) return;		/* Don't replace */
			break;
		}
	}
	*env= entry;
}
#endif
