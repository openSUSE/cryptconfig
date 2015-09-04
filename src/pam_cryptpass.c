/*
 * Copyright (c) 2007 Novell, Inc. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact Novell, Inc.
 *
 * To contact Novell about this file by physical or electronic mail, 
 * you may find current contact information at www.novell.com.
 *
 */

/*
 * A pam module to sync a user's password with the password
 * used to encrypt the key for their encrypted home directory.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>

#include "cryptconfig.h"

/*
 * Set key_file to the key file for user, if it exists. 
 */
static int get_key_file (const char *user, char *key_file, size_t kf_len)
{
    char *key_f = NULL, *image_f = NULL;
    struct passwd *pent;
    struct stat info;
    int key_fd, ret = -1;

    pent = getpwnam (user);
    if (!pent)
        return -1;

    if (!pam_mount_is_setup_for_user (user, &image_f, &key_f, NULL))
        return -1;

    /* make sure the key exists and user is the owner */
    key_fd = open (key_f, O_RDONLY | O_NOFOLLOW);
    if (key_fd == -1)
        goto done;

    if (!fstat (key_fd, &info) && pent->pw_uid == info.st_uid) {
        strncpy (key_file, key_f, kf_len -1);
        key_file[kf_len - 1] = '\0';
        ret = 0;
    }
    
    close (key_fd);

done:
    g_free (image_f);
    g_free (key_f);
    return ret;
}

/*
 * There's a chance, when using non-local auth methods, that
 * the key file password and the auth password will be out of
 * sync.  If we can detect this then we prompt for the old password
 * and sync the key.
 */
static int prompt_for_old_auth_token (pam_handle_t *pamh, char **authtok)
{
    int ret;
    struct pam_conv *conv = NULL;
    struct pam_message msg;
    const struct pam_message *pmsg = &msg;
    struct pam_response *res = NULL;

    ret = pam_get_item (pamh, PAM_CONV, (void *) &conv);
    if (ret != PAM_SUCCESS || !conv) {
        syslog (LOG_ERR, "Unable to get pam conversation data.\n");
        return 1;
    }

    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = _("Enter key file password");

    ret = conv->conv (1, &pmsg, &res, conv->appdata_ptr);
    if (ret != PAM_SUCCESS || !res) {
        syslog (LOG_ERR, "Unable to converse with the application.\n");
        return 1;
    }

    *authtok = strdup (res->resp);
    return 0;
}

/*
 * Decrypt the key file with old_pw and encrypt it with new_pw.
 */
static int sync_key_file (const char *user, char *key_file, char *old_pw, char *new_pw)
{
    char *key_data = NULL;
    struct passwd *pent;
    int key_size, key_fd;
    gboolean ret;
    
    ret = decrypt_key (key_file, old_pw, &key_data, &key_size);
    if (ret == FALSE) {
        syslog (LOG_ERR, "Failed to decrypt key with old authtok\n");
        return PAM_AUTHTOK_RECOVERY_ERR;
    }

    ret = encrypt_key (key_file, new_pw, key_data, key_size);
    if (ret == FALSE) {
        syslog (LOG_ERR, "Failed to encrypt key with new authtok\n");
        memset (key_data, 0, key_size);
        munlock (key_data, key_size);
        free (key_data);
        return PAM_AUTHTOK_ERR;
    }

    memset (key_data, 0, key_size);
    munlock (key_data, key_size);
    free (key_data);
    
    /* change the owner of the fs key to the user */
    pent = getpwnam (user);
    if (!pent) {
        syslog (LOG_ERR, "Failed to lookup user\n");
        return PAM_AUTHTOK_ERR;
    }

    key_fd = open (key_file, O_RDONLY | O_NOFOLLOW);
    if (key_fd == -1) {
        syslog (LOG_ERR, "Failed to open %s: %s\n", key_file, strerror (errno));
        return PAM_AUTHTOK_ERR;
    }

    if (fchown (key_fd, pent->pw_uid, 0)) {
        syslog (LOG_ERR, "Failed to change the owner of %s: %s\n", key_file, strerror (errno));
        close (key_fd);
        return PAM_AUTHTOK_ERR;
    }

    close (key_fd);
    syslog (LOG_INFO, "Password for %s was successfully changed.\n", key_file);
    return PAM_SUCCESS;
}

/*
 * The pam function called when the authok is changed.
 */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    const char *user;
    int ret;
    char key_file[PATH_MAX];

    /* get user name */
    ret = pam_get_user (pamh, &user, NULL);
    if (ret != PAM_SUCCESS)
        return ret;

    /* find the user's key file */
    ret = get_key_file(user, key_file, PATH_MAX);
    if (ret == -1)
        return PAM_USER_UNKNOWN;

    /*
     * We need the old authtok to be able to decrypt
     * the key and the root can't provide this.
     */
    if (getuid () == 0) {
        syslog (LOG_ERR, "Unable to update file system key %s since "
                         "password is being changed by root\n", key_file);
        return PAM_AUTHTOK_RECOVERY_ERR;
    }
    
    if (flags & PAM_PRELIM_CHECK) {
        /* 
         * If we get here then we have a key file for user,
         * which is all we need to verify for PAM_PRELIM_CHECK.
         */
        return PAM_SUCCESS;
    } else if (flags & PAM_UPDATE_AUTHTOK) {
        char *pass_old = NULL, *pass_new = NULL;

        /* update the password used to encrypt the key */
        ret = pam_get_item (pamh, PAM_OLDAUTHTOK, (void *) &pass_old);
        if (ret != PAM_SUCCESS || pass_old == NULL) {
            syslog (LOG_ERR, "Failed to get old authtok\n");
            return PAM_AUTHTOK_RECOVERY_ERR;
        }

        ret = pam_get_item (pamh, PAM_AUTHTOK, (void *) &pass_new);
        if (ret != PAM_SUCCESS || pass_new == NULL) {
            syslog (LOG_ERR, "Failed to get new authtok\n");
            return PAM_AUTHTOK_ERR;
        }

        return sync_key_file (user, key_file, pass_old, pass_new);
    } else {
        /* things are not good */
        return PAM_ABORT;
    }
}

/*
 * We need this since we provide open_session, but we
 * don't need to do anything
 */
PAM_EXTERN int pam_sm_close_session (pam_handle_t *pamh, int flags,
                                     int argc, const char **argv)
{
    return PAM_IGNORE;
}

/*
 * We need to get the authtok pam_mount is going to try and use
 * and make sure that we can decrypt the fs key.  If we can't then
 * the key is out of sync and we can prompt for the old authtok.
 */
PAM_EXTERN int pam_sm_open_session (pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    char *pass_curr = NULL, *pass_old = NULL, *key_data = NULL;
    const char *user;
    int ret, key_size;
    char key_file[PATH_MAX];
   
    /* Get the user name */
    ret = pam_get_user (pamh, &user, NULL);
    if (ret != PAM_SUCCESS)
        return PAM_IGNORE;

    /* Don't do anything if the user isn't using an encrypted home dir */
    ret = get_key_file(user, key_file, PATH_MAX);
    if (ret == -1)
        return PAM_IGNORE;

    /* Get the authtok that pam_mount stores in the auth stack */
    ret = pam_get_data (pamh, "pam_mount_system_authtok", (void *) &pass_curr);
    if (ret != PAM_SUCCESS || pass_curr == NULL) {
        syslog (LOG_ERR, "Failed to get pam_mount authtok\n");
        return PAM_IGNORE;
    }

    /*
     * Try and decrypt the key.  If we can't decrypt the key then
     * we prompt for the old auth token.
     */
    if (!decrypt_key (key_file, pass_curr, &key_data, &key_size)) {
        if (!prompt_for_old_auth_token (pamh, &pass_old)) {
            int r = sync_key_file (user, key_file, pass_old, pass_curr);
            free (pass_old);
            return r;
        } else {
            syslog (LOG_ERR, "Failed to decrypt key with both authtoks\n");
            return PAM_SESSION_ERR;
        }
    } else {
        memset (key_data, 0, key_size);
        munlock (key_data, key_size);
        free (key_data);
        return PAM_SUCCESS;
    }
}
