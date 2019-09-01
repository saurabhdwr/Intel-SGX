#ifndef _PWD_H_
#define	_PWD_H_

#include <sys/types.h>
#include "unistd.h"
#if __BSD_VISIBLE
#define	_PATH_PASSWD		"/etc/passwd"
#define	_PATH_MASTERPASSWD	"/etc/master.passwd"
#define	_PATH_MASTERPASSWD_LOCK	"/etc/ptmp"

#define	_PATH_MP_DB		"/etc/pwd.db"
#define	_PATH_SMP_DB		"/etc/spwd.db"

#define	_PATH_PWD_MKDB		"/usr/sbin/pwd_mkdb"

#define	_PW_KEYBYNAME		'1'	/* stored by name */
#define	_PW_KEYBYNUM		'2'	/* stored by entry in the "file" */
#define	_PW_KEYBYUID		'3'	/* stored by uid */

#define _PW_YPTOKEN		"__YP!"

#define	_PASSWORD_EFMT1		'_'	/* extended encryption format */

#define	_PASSWORD_LEN		128	/* max length, not counting NUL */
#define	_PW_NAME_LEN		31	/* max length, not counting NUL */
/* Should be MAXLOGNAME - 1 */
#define _PW_BUF_LEN		1024	/* length of getpw*_r buffer */

#define _PASSWORD_NOUID		0x01	/* flag for no specified uid. */
#define _PASSWORD_NOGID		0x02	/* flag for no specified gid. */
#define _PASSWORD_NOCHG		0x04	/* flag for no specified change. */
#define _PASSWORD_NOEXP		0x08	/* flag for no specified expire. */

/* Flags for pw_mkdb(3) */
#define	_PASSWORD_SECUREONLY	0x01	/* only generate spwd.db file */
#define	_PASSWORD_OMITV7	0x02	/* don't generate v7 passwd file */

#endif

struct passwd {
	char	*pw_name;		/* user name */
	char	*pw_passwd;		/* encrypted password */
	uid_t	pw_uid;			/* user uid */
	gid_t	pw_gid;			/* user gid */
	time_t	pw_change;		/* password change time */
	char	*pw_class;		/* user access class */
	char	*pw_gecos;		/* Honeywell login info */
	char	*pw_dir;		/* home directory */
	char	*pw_shell;		/* default shell */
	time_t	pw_expire;		/* account expiration */
};
struct passwd	*getpwuid(uid_t);
struct passwd	*getpwnam(const char *);
struct passwd	*getpwuid_shadow(uid_t);
struct passwd	*getpwnam_shadow(const char *);
int		getpwnam_r(const char *, struct passwd *, char *, size_t,
	struct passwd **);
int		getpwuid_r(uid_t, struct passwd *, char *, size_t,
	struct passwd **);
#if __BSD_VISIBLE || __XPG_VISIBLE
struct passwd	*getpwent(void);
void		 setpwent(void);
void		 endpwent(void);
#endif
#if __BSD_VISIBLE
int		 setpassent(int);
int		 uid_from_user(const char *, uid_t *);
const char	*user_from_uid(uid_t, int);
char		*bcrypt_gensalt(u_int8_t);
char		*bcrypt(const char *, const char *);
int		bcrypt_newhash(const char *, int, char *, size_t);
int		bcrypt_checkpass(const char *, const char *);
struct passwd	*pw_dup(const struct passwd *);
#endif
#endif
