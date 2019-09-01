//
// sys/types.h
//
//      Copyright (c) Microsoft Corporation. All rights reserved.
//
// Types used for returning file status and time information.
//

#ifndef _INO_T_DEFINED
    #define _INO_T_DEFINED

    typedef unsigned short _ino_t; // inode number (unused on Windows)

    #if !__STDC__
        typedef _ino_t ino_t;
    #endif
#endif



#ifndef _DEV_T_DEFINED
    #define _DEV_T_DEFINED

    typedef unsigned int _dev_t; // device code

    #if !__STDC__
        typedef _dev_t dev_t;
    #endif
#endif



#ifndef _OFF_T_DEFINED
    #define _OFF_T_DEFINED

    typedef long _off_t; // file offset value

    #if !__STDC__
        typedef _off_t off_t;
    #endif
#endif

#ifndef _UID_T_DEFINED
#define _UID_T_DEFINE
		typedef unsigned int uid_t; //user id
#if !__STDC__
		typedef uid_t uid_t;
#endif
#endif

#ifndef _GID_T_DEFINED
#define _GID_T_DEFINED
		typedef unsigned int gid_t;
#if !__STDC__
		typedef gid_t gid_t;
#endif
#endif
