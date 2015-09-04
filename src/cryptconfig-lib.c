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

#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <termios.h>
#include <linux/loop.h>
#include <openssl/evp.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <libxml/tree.h>

#include "cryptconfig.h"

typedef enum {
    PAM_CONFIG_TYPE_MOUNT,
    PAM_CONFIG_TYPE_CRYPTPASS,
    PAM_CONFIG_TYPE_CRYPTPASS_PASSWD
} PamConfigType;

typedef enum {
    PAM_CONFIG_OP_ADD,
    PAM_CONFIG_OP_REMOVE
} PamConfigOp;

typedef gboolean (*LineMatchFunc) (char *, void *);

static long fs_min_sizes[] = { 10, 10, 40 };
static gchar *fs_list[] = { "ext3", "ext2", "reiserfs" };
static gchar *default_pam_services[] = { "gdm", "login", "kdm", "xdm", "sudo", NULL };
static gchar *default_cryptpass_services[] = { "passwd", "gnome-passwd", NULL };

/*
 * Manually copy the contents of old to new
 */
static int copy_file (const char *old, const char *new)
{
    ssize_t br, bw;
    int old_fd, new_fd, ret = 0;
    char buff[BUFSIZ];
    
    old_fd = open (old, O_RDONLY);
    if (old_fd == -1) {
        g_printerr ("open: %s\n", strerror (errno));
        return -1;
    }

    new_fd = open (new, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (new_fd == -1) {
        close (old_fd);
        g_printerr ("open: %s\n", strerror (errno));
        return -1;
    }

    while (1) {
        br = read (old_fd, buff, BUFSIZ);
        if (br < 1) {
            ret = br;
            break;
        }

        bw = write (new_fd, buff, br);
        if (bw != br) {
            ret = -1;
            break;
        }
    }

    close (new_fd);
    close (old_fd);
    return ret;
}

static gboolean move_file (char *old, char *new)
{
    gchar *argv[] = { "/bin/mv", "-f", old, new, NULL };
    GError *err = NULL;
    gint status;
   
    gboolean ret = g_spawn_sync (NULL, argv, NULL,
                                 G_SPAWN_STDOUT_TO_DEV_NULL,
                                 NULL, NULL, NULL, NULL, &status, &err);
    if (!ret || WEXITSTATUS (status) != 0) {
        g_printerr (_("move failed: %s\n"), err->message);
        g_error_free (err);
        return FALSE;
    }

    return TRUE; 
}

/*
 * Rename old to new, but keep new's permissions, uid, and guid.
 */
static gboolean overwrite_file (const char *old, const char *new)
{
    int retval, new_fd;
    struct stat info;

    if (!g_file_test (old, G_FILE_TEST_EXISTS) ||
        !g_file_test (new, G_FILE_TEST_EXISTS)) {
        g_printerr ("access: %s\n", strerror (errno));
        return FALSE;
    }

    if (g_stat (new, &info)) {
        g_printerr ("stat: %s\n", strerror (errno));
        return FALSE;
    }

    /*
     * If rename fails because the files are on different
     * devices then we use a crappy rename/copy.
     */
    retval = rename (old, new);
    if (retval == -1 && errno == EXDEV) {
        retval = copy_file (old, new);

        if (retval)
            unlink (old);
    }

    if (retval)
        return FALSE;

    new_fd = open (new, O_RDONLY | O_NOFOLLOW);
    if (new_fd == -1) {
        g_printerr ("open: %s\n", strerror (errno));
        return FALSE;
    }

    if (fchmod (new_fd, info.st_mode)) {
        g_printerr ("fchmod: %s\n", strerror (errno));
        close (new_fd);
        return FALSE;
    }

    if (fchown (new_fd, info.st_uid, info.st_gid)) {
        g_printerr ("fchown: %s\n", strerror (errno));
        close (new_fd);
        return FALSE;
    }

    close (new_fd);
    return TRUE;
}

/*
 * Create a new loop device.  The device string must be freed by
 * the caller.
 */
static gboolean loop_create_new_device (int nr, gchar **device)
{
    struct stat info;

    if (g_stat ("/dev/loop0", &info)) {
        /* prefill info with reasonable defaults */
        info.st_mode = S_IFBLK | 0600;
        info.st_uid = 0; /* root */
        info.st_gid = 0; /* root, to be on the safe side */
    }

    *device = g_strdup_printf ("/dev/loop%d", nr);

    if (mknod (*device, info.st_mode | S_IFBLK, makedev (7, nr)) ||
        chown (*device, info.st_uid, info.st_gid) ||
        chmod (*device, info.st_mode)) { 
        g_free (*device);
        return FALSE;
    }

    return TRUE;
}

/*
 * Return the path of an unused loop device.  We'll
 * create a new loop device if we have to. The device 
 * string must be freed by the caller.
 */
static gboolean loop_get_open_device (gchar **device)
{
    int i;
    
    for (i = 0; i < 256; i++) {
        int fd;
        struct loop_info loopinfo;
        char dev[16];

        dev[15] = '\0';
        snprintf (dev, 15, "/dev/loop%d", i);
        
        if (!g_file_test (dev, G_FILE_TEST_EXISTS))
            return loop_create_new_device (i, device);

        fd = open (dev, O_RDONLY);
        if (fd == -1)
            continue;

        /* This fails with errno set to ENXIO if the device isn't used */
        if (ioctl (fd, LOOP_GET_STATUS, &loopinfo) == -1 && errno == ENXIO) {
            close (fd);
            *device = g_strdup_printf ("/dev/loop%d", i);
            return TRUE;
        }

        close (fd);
    }

    return FALSE;
}

/*
 * Gets the total size of a directory in MB.
 */
static gboolean get_directory_size (char *directory, guint64 *size)
{
    gchar *argv[] = { DU_BIN_PATH, "-shk", "--", directory, NULL };
    gchar *std_out;
    gboolean ret;
    gint status;
    int r;

    ret = g_spawn_sync (NULL, argv, NULL, G_SPAWN_STDERR_TO_DEV_NULL,
                        NULL, NULL, &std_out, NULL, &status, NULL);
    if (!ret || WEXITSTATUS(status) != 0)
        return FALSE;
   
    r = sscanf (std_out, "%llu", size);
    g_free (std_out);
    if (r < 1)
        return FALSE;
  
    *size = *size / 1024;
    return TRUE;
}

/*
 * Get the list of pam services we need to modify.  The list should
 * be freed with g_strfreev().  We try and read the list from our
 * conf and fall back to a default list if we have problems.
 */
static gchar **get_pam_services (gsize *size)
{
    gchar **list = NULL, **ret = NULL;
    GKeyFile *kf = g_key_file_new ();
    gsize len;
    int i;

    if (!g_key_file_load_from_file (kf, CRYPTCONFIG_CONF, G_KEY_FILE_NONE, NULL) ||
        !g_key_file_has_group (kf, "PAM")) {
        g_printerr (_("Failed to load " CRYPTCONFIG_CONF ", using default list\n"));
        list = g_strdupv (default_pam_services);
        len = sizeof (default_pam_services) / sizeof (default_pam_services[0]) - 1;
    } else {
        list = g_key_file_get_string_list (kf, "PAM", "Services", &len, NULL);
        if (!list) {
            g_printerr (_("Failed to load service list from " CRYPTCONFIG_CONF ", using default list\n"));
            list = g_strdupv (default_pam_services);
            len = sizeof (default_pam_services) / sizeof (default_pam_services[0]) - 1;
        }
    }

    ret = g_new (gchar *, len + 1);
    ret[len] = NULL;
    *size = len;

    for (i = 0; i < len && list; i++) {
        ret[i] = g_strdup (list[i]);
    }

    g_strfreev (list);
    g_key_file_free (kf);
    return ret;
}

/*
 * Get the list of pam passwd services we need to modify.  The list should
 * be freed with g_strfreev().  We try and read the list from our
 * conf and fall back to a default list if we have problems.
 */
static gchar **get_pam_passwd_services (gsize *size)
{
    gchar **list = NULL, **ret = NULL;
    GKeyFile *kf = g_key_file_new ();
    gsize len;
    int i;

    if (!g_key_file_load_from_file (kf, CRYPTCONFIG_CONF, G_KEY_FILE_NONE, NULL) ||
        !g_key_file_has_group (kf, "PAM")) {
        g_printerr (_("Failed to load " CRYPTCONFIG_CONF ", using default list\n"));
        list = g_strdupv (default_cryptpass_services);
        len = sizeof (default_cryptpass_services) / sizeof (default_cryptpass_services[0]) - 1;
    } else {
        list = g_key_file_get_string_list (kf, "PAM", "PasswordServices", &len, NULL);
        if (!list) {
            g_printerr (_("Failed to load service list from " CRYPTCONFIG_CONF ", using default list\n"));
            list = g_strdupv (default_cryptpass_services);
            len = sizeof (default_cryptpass_services) / sizeof (default_cryptpass_services[0]) - 1;
        }
    }

    ret = g_new (gchar *, len + 1);
    ret[len] = NULL;
    *size = len;

    for (i = 0; i < len && list; i++) {
        ret[i] = g_strdup (list[i]);
    }

    g_strfreev (list);
    g_key_file_free (kf);
    return ret;
}

/*
 * Run pam-config to add/remove pam_mount to/from the service configs.
 */
static gboolean run_pam_config (PamConfigType type, PamConfigOp op) 
{
    char *flags[] = { "--mount", "--cryptpass", "--cryptpass-password" };
    char *operation = op == PAM_CONFIG_OP_ADD ? "-a" : "-d";
    gboolean ret = TRUE;
    gchar **list;
    gsize size;
    int i;

    list = type == PAM_CONFIG_TYPE_CRYPTPASS_PASSWD ?
           get_pam_passwd_services (&size) : get_pam_services (&size);
    
    if (!list) {
        g_printerr (_("Failed to get pam services list\n"));
        return FALSE;
    }
    
    for (i = 0; i < size; i++) {
        char *argv[] = { PAMCONFIG_BIN_PATH, "--service", list[i], operation, flags[type], NULL };
        GError *err = NULL;
        gint status;
        gchar *fn;
        gboolean r;
       
        if (!list[i])
            break;
        
        fn = g_build_filename (PAM_SERVICES_DIR, list[i], NULL);
        r = g_file_test (fn, G_FILE_TEST_EXISTS);
        g_free (fn);
        if (!r)
            continue;
        
        if (!g_spawn_sync (NULL, argv, NULL,
                           G_SPAWN_STDOUT_TO_DEV_NULL,
                           NULL, NULL, NULL, NULL, &status, &err)) {
            g_printerr ("Failed to execute %s: %s\n", PAMCONFIG_BIN_PATH, err->message);
            g_error_free (err);
            continue;
        }
  
        if (WEXITSTATUS (status)) {
            g_printerr ("Failed to modify %s\n", list[i]);
            ret = FALSE;
        }
    }

    g_strfreev (list);
    return ret;
}

/*
 * Return TRUE is user has an entry in pam_mount.conf.  The image, key, and fs_type
 * arguments should be freed by the caller if the function returns true.
 */
gboolean pam_mount_is_setup_for_user (const char *user, char **image, char **key, char **fs_type)
{
    xmlDocPtr doc;
    xmlNodePtr root_node, node;
    int ret = FALSE;

    doc = xmlParseFile (PAM_MOUNT_CONF);
    if (!doc) {
        g_printerr ("Failed to read %s\n", PAM_MOUNT_CONF);
        return FALSE;
    }

    root_node = xmlDocGetRootElement (doc);   
    if (!root_node) {
        g_printerr ("Failed to get root element from %s\n", PAM_MOUNT_CONF);
        return FALSE;
    }
   
    for (node = root_node->children; node; node = node->next) {
        xmlChar *fstype, *usr, *fskeypath, *path;

        if (node->type != XML_ELEMENT_NODE)
            continue;

        if (xmlStrcasecmp ((xmlChar *) "volume", node->name))
            continue;

        fstype = xmlGetProp (node, (xmlChar *) "fstype");
        usr = xmlGetProp (node, (xmlChar *) "user");
        path = xmlGetProp (node, (xmlChar *) "path");
        fskeypath = xmlGetProp (node, (xmlChar *) "fskeypath");
 
        if (fstype && usr && path && fskeypath &&
            !xmlStrcasecmp ((xmlChar *) fstype, (xmlChar *) "crypt") &&
            !xmlStrcasecmp (usr, (xmlChar *) user)) {
            if (image)
                *image = g_strchomp (strdup ((char *) path));
            
            if (key)
                *key = g_strchomp (strdup ((char *) fskeypath));
            
            if (fs_type)
                *fs_type = g_strchomp (strdup ((char *) fstype));

            ret = TRUE;
        }

        xmlFree (fstype);
        xmlFree (usr);
        xmlFree (path);
        xmlFree (fskeypath);

        if (ret)
            break;
    }

    xmlFreeDoc (doc);
    return ret;
}

/*
 * A helper to run cryptsetup with passphrase sent to stdin
 */
static gboolean spawn_cryptsetup (char *argv[], const char *pass, size_t pass_size) {
    GError *err = NULL;
    gboolean ret, retval = TRUE;
    gint std_in;
    int status;
    GPid child_pid;

    ret = g_spawn_async_with_pipes (NULL, argv, NULL,
                                    G_SPAWN_DO_NOT_REAP_CHILD |
                                    G_SPAWN_STDOUT_TO_DEV_NULL,
                                    NULL, NULL, &child_pid, &std_in, NULL, NULL, &err);
    if (!ret) {
        g_printerr ("%s\n", err->message);
        g_error_free (err);
        return FALSE;
    }
   
    if (pass != NULL && write (std_in, pass, pass_size) != pass_size)
        retval = FALSE;

    close (std_in);

    if (waitpid (child_pid, &status, 0) == -1 || WEXITSTATUS (status) != 0)
        retval = FALSE;

    g_spawn_close_pid (child_pid);
    return retval;
}

/*
 * LUKS format a device using the supplied passphrase.
 */
gboolean luks_format (const char *pass, size_t pass_size, char *device)
{
    char *argv[] = { CRYPTSETUP_BIN_PATH, "-q", "luksFormat", device, NULL};
    return spawn_cryptsetup (argv, pass, pass_size);
}

/*
 * Open an existing LUKS device using the passphrase.  The mapped device will
 * be /dev/mapper/$map_name.
 */
gboolean luks_open (const char *pass, size_t pass_size, char *device, char *map_name)
{
    char *argv[] = { CRYPTSETUP_BIN_PATH, "luksOpen", device, map_name, NULL};
    return spawn_cryptsetup (argv, pass, pass_size);
}

/*
 * Close a mapped LUKS device.
 */
gboolean luks_close (char *map_name) 
{
    char *argv[] = { CRYPTSETUP_BIN_PATH, "luksClose", map_name, NULL};
    return spawn_cryptsetup (argv, NULL, 0);
}

/*
 * Add a new key to a LUKS device.
 */
gboolean luks_add_key (char *device, char *existing_key, size_t ek_size,
                       char *new_key, size_t nk_size)
{
    char *argv[] = { CRYPTSETUP_BIN_PATH, "luksAddKey", device, NULL};
    GError *err = NULL;
    gboolean ret, retval = FALSE;
    gint std_in;
    int status;
    GPid child_pid;

    ret = g_spawn_async_with_pipes (NULL, argv, NULL,
                                    G_SPAWN_DO_NOT_REAP_CHILD |
                                    G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                                    NULL, NULL, &child_pid, &std_in, NULL, NULL, &err);
    if (!ret) {
        g_printerr ("%s\n", err->message);
        g_error_free (err);
        return FALSE;
    }
  
    if (write (std_in, existing_key, ek_size) != ek_size)
        goto cleanup;

    if (write (std_in, "\n", 1) != 1)
        goto cleanup;

    if (write (std_in, new_key, nk_size) != nk_size)
        goto cleanup;

    if (write (std_in, "\n", 1) != 1)
        goto cleanup;

    if (write (std_in, new_key, nk_size) != nk_size)
        goto cleanup;
    
    retval = TRUE;

cleanup:
    close (std_in);

    if (waitpid (child_pid, &status, 0) == -1 || WEXITSTATUS (status) != 0)
        retval = FALSE;

    g_spawn_close_pid (child_pid);
    return retval;
}

/*
 * Decrypt the encrypted key file using password. The key_data
 * field needs to be unlocked and freed by the caller.
 */
gboolean decrypt_key (const char *key_file, const char *password,
                      char **key_data, int *key_data_size)
{
    const EVP_CIPHER *cipher = EVP_aes_256_cbc ();
    const EVP_MD *md = EVP_md5 ();
    size_t hk_sz, total_size = 0;
    int fd, final_size, kd_size;
    gboolean ret = FALSE;
    struct stat info;
    EVP_CIPHER_CTX ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char hashed_key[EVP_MAX_KEY_LENGTH];
    unsigned char salt[PKCS5_SALT_LEN];
    unsigned char magic[8];

    fd = open (key_file, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) {
        g_printerr ("open: %s\n", strerror (errno));
        return FALSE;
    }

    /* make sure the key_file is below our size threshold */
    if (fstat (fd, &info)) {
        g_printerr ("open: %s\n", strerror (errno));
        return FALSE;
    } else if (info.st_size > KEY_FILE_SIZE_THRESHOLD) {
        g_printerr (_("key file is too large\n"));
        return FALSE;
    }

    EVP_CIPHER_CTX_init (&ctx); 
    
    /* check the magic in the key and read the salt */
    if (read (fd, magic, 8) != 8 || memcmp (magic, "Salted__", 8))
        goto error;

    if (read (fd, salt, PKCS5_SALT_LEN) != PKCS5_SALT_LEN)
        goto error;
    
    /* hash the password to get the actual ciphertext key and iv */
    hk_sz = EVP_BytesToKey (cipher, md, salt, (unsigned char *) password,
                            strlen ((char *) password), 1, hashed_key, iv);
    if (hk_sz < 1)
        goto error;

    if (!EVP_DecryptInit_ex (&ctx, cipher, NULL, hashed_key, iv))
        goto error;
 
    kd_size = 0;
    total_size = 10 * EVP_MAX_BLOCK_LENGTH;
    *key_data = g_malloc (total_size);
    mlock (*key_data, total_size);

    while (1) {
        size_t n;
        int ds;
        unsigned char cipher_text[EVP_MAX_BLOCK_LENGTH];

        /* read a block of cipher_text */
        n = read (fd, cipher_text, EVP_MAX_BLOCK_LENGTH);
        if (n == -1)
            goto error;
        if (!n)
            break;
        
        /* make sure we have enough space for the next block operation */
        if (total_size - kd_size < n + EVP_MAX_BLOCK_LENGTH) {
            total_size *= 2;
            *key_data = g_realloc (*key_data, total_size);
            mlock (*key_data, total_size);
        }

        if (!EVP_DecryptUpdate (&ctx, (unsigned char *) *key_data + kd_size,
                                &ds, cipher_text, n))
            goto error;

        kd_size += ds;
    }

    /* make sure we have enough room for the rest of the data */
    if (total_size - kd_size < EVP_MAX_BLOCK_LENGTH) {
        total_size *= 2;
        *key_data = g_realloc (*key_data, total_size);
        mlock (*key_data, total_size);
    }

    /* write out any remaining buffered data */
    if (!EVP_DecryptFinal_ex (&ctx, (unsigned char *) *key_data + kd_size,
                              &final_size))
        goto error;

    *key_data_size = kd_size + final_size;
    ret = TRUE;

error:
    if (!ret && key_data) {
        memset (*key_data, 0, total_size);
        munlock (*key_data, total_size);
        g_free (*key_data);
        *key_data = NULL;
    }
    
    close (fd);
    EVP_CIPHER_CTX_cleanup (&ctx);
    return ret;
}

/*
 * Encrypt key_data using the new password 
 */
gboolean encrypt_key (const gchar *key_file, const char *pass_new,
                      const char *key_data, int key_size)
{
    const EVP_CIPHER *cipher = EVP_aes_256_cbc ();
    const EVP_MD *md = EVP_md5 (); 
    unsigned char *cipher_text = NULL;
    GError *err = NULL;
    gchar *tmp_name;
    size_t hk_sz;
    int fd, fdrand, ct_len, retval = 0;
    EVP_CIPHER_CTX ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char hashed_key[EVP_MAX_KEY_LENGTH];
    unsigned char salt[PKCS5_SALT_LEN];
    
    fd = g_file_open_tmp ("key-XXXXXX", &tmp_name, &err);
    if (fd == -1) {
        g_error_free (err);
        return FALSE;
    }

    fdrand = open ("/dev/urandom", O_RDONLY);
    if (fdrand == -1) {
        close (fd);
        g_printerr ("open: %s\n", strerror (errno));
        return FALSE;
    }
    
    /*
     * read a random salt block 
     */
    if (read (fdrand, salt, PKCS5_SALT_LEN) != PKCS5_SALT_LEN) {
        close (fdrand);
        close (fd);
        return FALSE;
    }

    EVP_CIPHER_CTX_init (&ctx);
    close (fdrand);

    /* write our magic and salt to the key file */
    if (write (fd, "Salted__", 8) != 8)
        goto error;

    if (write (fd, salt, sizeof (salt)) != sizeof (salt))
        goto error;
   
    /* hash the password to get the actual cipher key and iv */
    hk_sz = EVP_BytesToKey (cipher, md, salt, (unsigned char *)pass_new,
                            strlen ((char *) pass_new), 1, hashed_key, iv);
    if (hk_sz < 1)
        goto error;

    if (!EVP_EncryptInit_ex (&ctx, cipher, NULL, hashed_key, iv))
        goto error;

    cipher_text = malloc (key_size + EVP_MAX_BLOCK_LENGTH);
    if (!cipher_text) {
        g_printerr ("malloc: %s\n", strerror (errno));
        goto error;
    }

    /* encrypt the data and write it to our key file */
    if (!EVP_EncryptUpdate (&ctx, cipher_text, &ct_len,
                            (unsigned char *) key_data, key_size))
        goto error;

    if (write (fd, cipher_text, ct_len) != ct_len)
        goto error;

    if (!EVP_EncryptFinal_ex (&ctx, cipher_text, &ct_len))
        goto error;

    if (write (fd, cipher_text, ct_len) != ct_len)
        goto error;
    
    retval = rename (tmp_name, key_file);
    if (retval)
        retval = copy_file (tmp_name, key_file);

error:
    close (fd);
    EVP_CIPHER_CTX_cleanup (&ctx);
    if (cipher_text)
        free (cipher_text);
    return retval ? FALSE : TRUE;
}

/*
 * loopback mount a disk image and return the name of the
 * loop device used.  The device string must be freed by
 * the caller.
 */
gboolean loop_open (const char *image, char **device)
{
    gboolean ret = FALSE;
    int fd, loop_fd;
    struct loop_info info;

    *device = NULL;
    if (!loop_get_open_device (device))
        return FALSE;

    loop_fd = open (*device, O_RDWR | O_LARGEFILE);
    if (loop_fd == -1) {
        g_free (*device);
        g_printerr ("read: %s\n", strerror (errno));
        return FALSE;
    }

    fd = open (image, O_RDWR | O_LARGEFILE);
    if (fd == -1) {
        g_free (*device);
        g_printerr ("read: %s\n", strerror (errno));
        close (loop_fd);
        return FALSE;
    }

    memset(&info, 0, sizeof(info));
    strncpy(info.lo_name, image, LO_NAME_SIZE);
    info.lo_name[LO_NAME_SIZE-1] = '\0';

    if (ioctl (loop_fd, LOOP_SET_FD, fd)) {
        g_printerr ("ioctl: %s\n", strerror (errno));
        goto cleanup;
    }

    if (ioctl (loop_fd, LOOP_SET_STATUS, &info)) {
        g_printerr ("ioctl: %s\n", strerror (errno));
        ioctl (loop_fd, LOOP_CLR_FD, 0);
        goto cleanup;
    }

    ret = TRUE;

cleanup:
    if (!ret)
        g_free (*device);
        
    close (loop_fd);
    close (fd);
    return ret;
}

/*
 * Given an image file find the mapped device and loop device using the image
 */
gboolean loop_find_devs_from_image (const char *image, gchar **map_dev,
                                    gchar **loop_dev)
{
    gchar *map_name = NULL, *md = NULL;
    gboolean ret = FALSE;
    int i;

    map_name = path_to_map_name (image);
    if (!map_name)
        return FALSE;

    md = g_build_filename ("/dev/mapper", map_name, NULL);
   
    if (!g_file_test (md, G_FILE_TEST_EXISTS)) {
        if (map_dev)
            *map_dev = NULL;
    } else {
        if (map_dev)
            *map_dev = g_strdup (md);
    }
    
    /* try and find the loop device that image is using */
    for (i = 0; i < 256; i++) {
        int fd, io_ret;
        struct loop_info64 info;
        char ld[BUFF_SIZE];

        ld[BUFF_SIZE - 1] = '\0';
        snprintf (ld, BUFF_SIZE - 1, "/dev/loop%d", i);

        fd = open (ld, O_RDONLY);
        if (fd == -1)
            break;

        io_ret = ioctl (fd, LOOP_GET_STATUS64, &info);
        close (fd);

        if (!io_ret) {
            if (!strcmp (image, (char *) info.lo_file_name)) {
                if (loop_dev)
                    *loop_dev = g_strdup (ld);
                ret = TRUE;
                goto cleanup;
            }
        }
    }

cleanup:
    if (!ret) {
        if (map_dev)
            *map_dev = NULL;
    }

    g_free (md);
    g_free (map_name);
    return ret;
}

/*
 * Free a used loop device.
 */
gboolean loop_close (const char *loop_device)
{
    int loop_fd = open (loop_device, O_RDONLY);
    if (loop_fd == -1) {
        perror ("open");
        return FALSE;
    }

    if (ioctl (loop_fd, LOOP_CLR_FD, 0)) {
        close (loop_fd);
        return FALSE;
    }

    close (loop_fd);
    return TRUE;
}

/*
 * Create an image file that's filled with zeros 
 */
gboolean create_image_zero (const char *image, guint64 size_in_mb)
{
    guint64 bytes = size_in_mb * 1048576;
    int fd = open (image, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_LARGEFILE, 0600);
    if (fd == -1) {
        perror ("open");
        return FALSE;
    }

    if (lseek64 (fd, bytes, SEEK_END) == -1) {
        close (fd);
        return FALSE;
    }
 
    if (write (fd, "\0", 1) == -1) {
        perror ("write");
        close (fd);
        return FALSE;
    }

    close (fd);
    return TRUE;
}

/*
 * Create an image file that's filled with random data 
 */
gboolean create_image_random (const char *image, guint64 size_in_mb)
{
    guint64 total = 0, target = size_in_mb * 1048576;
    int fd, randfd;
    gboolean ret;
    char buff[BUFSIZ];
    
    fd = open (image, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_LARGEFILE, 0600);
    if (fd == -1) {
        perror ("open");
        return FALSE;
    }

    randfd = open ("/dev/urandom", O_RDONLY);
    if (randfd == -1) {
        g_printerr ("open: %s\n", strerror (errno));
        close (fd);
        return FALSE;
    }

    do {
        ssize_t n = read (randfd, buff, BUFSIZ);
        if (n == -1) {
            goto error;
        } else {
            total += n;

            if (write (fd, buff, n) == -1)
                goto error;
        }
    } while (total < target);

    ret = TRUE;
error:
    close (fd);
    close (randfd);
    return ret;
}

/*
 * See if fs_type is in our support filesystem list
 */
gboolean is_filesystem_supported (const char *fs_type)
{
    int i, size = sizeof(fs_list) / sizeof(fs_list[0]);

    for (i = 0; i < size; i++) {
        if (!strncmp (fs_type, fs_list[i], strlen (fs_list[i])))
            return TRUE;
    }

    return FALSE;
}

/*
 * Get the list of supported fs.  The result needs to be freed
 * with g_free ().
 */
gchar *get_supported_filesystems (void) 
{
    gchar *ret;
    int i, size = sizeof(fs_list) / sizeof(fs_list[0]);
    GString *str = g_string_new (NULL);

    for (i = 0; i < size; i++) {
        if (i)
            str = g_string_append (str, ", ");
        str = g_string_append (str, fs_list[i]);
    }

    ret = str->str;
    g_string_free (str, FALSE);
    return ret;
}

/*
 * Create a file system on a device if the fs_type is in our support
 * file system list.
 */
gboolean create_filesystem (char *device, char *fs_type)
{
    char *argv[] = { MKFS_BIN_PATH, "-t", fs_type, "-q", "--", device, NULL };
    GError *err;
    gint status;
    gboolean ret;
    
    ret = g_spawn_sync (NULL, argv, NULL,
                        G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                        NULL, NULL, NULL, NULL, &status, &err);
    if (!ret) {
        g_error_free (err);
        return FALSE;
    }
    
    return WEXITSTATUS (status) ? FALSE : TRUE;
}

/*
 * Make sure the image size is greater than the minimum allowed size
 * for the chosen file system.
 */
gboolean check_min_fs_size (const char *fs_type, gint64 image_size, gint64 *req_size)
{
    int i, len = sizeof(fs_min_sizes)/sizeof(fs_min_sizes[0]);

    for (i = 0; i < len; i++) {
        if (!strcmp (fs_list[i], fs_type)) {
            *req_size = fs_min_sizes[i];
            return image_size >= fs_min_sizes[i] ? TRUE : FALSE;
        }
    }

    return FALSE;
}

/*
 * Ensure that we have at least 'size' bytes available on the partition
 * containing 'path'.
 */
gboolean check_requested_space (const char *path, guint64 req_size)
{
    guint64 free_space;
    struct statvfs info;
    gchar *dir;

    memset (&info, 0, sizeof (info));
    dir = g_path_get_dirname (path);
    
    if (statvfs (dir, &info) == -1) {
        g_printerr ("statvfs: %s\n", strerror (errno));
        g_free (dir);
        return FALSE;
    }

    g_free (dir);
    free_space = info.f_bavail * (guint64) info.f_bsize;
    free_space = free_space / 1048576;
    
    return free_space > req_size ? TRUE : FALSE;
}

/*
 * Ensures that there is enough space to copy a user's current home
 * directory to it's encrypted disk image.
 */
gboolean check_disk_space (char *image, char *current_home, guint64 *home_size)
{
    guint64 free_space;
    struct statvfs info;
    gchar *dir;
  
    memset (&info, 0, sizeof (info));
    dir = g_path_get_dirname (image);
    
    if (statvfs (dir, &info) == -1) {
        g_printerr ("statvfs: %s\n", strerror (errno));
        g_free (dir);
        return FALSE;
    }

    g_free (dir);
    free_space = info.f_bavail * (guint64) info.f_bsize;
    free_space = free_space / 1048576;
    
    if (!get_directory_size (current_home, home_size))
        return FALSE;

    return free_space > *home_size ? TRUE : FALSE;
}

/* 
 * Write our changes to a temp file and, if everything went ok, 
 * overwrite the pam_mount conf.
 */
static int write_xml_config (xmlDocPtr doc)
{
    gchar *tmp_name;
    int ret;

    int fd = g_file_open_tmp ("pam-mount-conf-XXXXXX", &tmp_name, NULL);
    if (fd == -1) {
        g_printerr (_("Failed to create temp file\n"));
        return -1;
    }

    ret = xmlSaveFormatFileEnc (tmp_name, doc, "UTF-8", 1);
    if (ret != -1)
        ret = overwrite_file (tmp_name, PAM_MOUNT_CONF) == TRUE ? 0 : -1;

    close (fd);
    return ret;
}

/*
 * Remove the crypt home directory entries for user in
 * the pam_mount conf file.  If user is NULL then we
 * remove all encrypted home entries.
 */
gboolean disable_pam_mount (const char *user)
{
    xmlDocPtr doc;
    xmlNodePtr root_node, node, next_node;
    struct passwd *pent;
    gboolean other_entries = FALSE;
    int ok;

    if (user) {
        pent = getpwnam (user);
        if (!pent) {
            g_printerr (_("Failed to lookup user %s\n"), user);
            return FALSE;
        }
    }

    doc = xmlParseFile (PAM_MOUNT_CONF);
    if (!doc) {
        g_printerr ("Failed to read %s\n", PAM_MOUNT_CONF);
        return FALSE;
    }

    root_node = xmlDocGetRootElement (doc);   
    if (!root_node) {
        g_printerr ("Failed to get root element from %s\n", PAM_MOUNT_CONF);
        return FALSE;
    }
    
    node = root_node->children;
    while (node) {
        xmlChar *u, *t;
        gboolean remove_node = FALSE;

        if (node->type != XML_ELEMENT_NODE ||
            xmlStrcasecmp ((xmlChar *) "volume", node->name)) {
            node = node->next;
            continue;
        }

        u = xmlGetProp (node, (xmlChar *) "user");
        t = xmlGetProp (node, (xmlChar *) "fstype");
        
        if (!u || !t || !xmlHasProp (node, (xmlChar *) "fskeypath") ||
            xmlStrcasecmp ((xmlChar *) "crypt", t)) {
            xmlFree (u);
            xmlFree (t);
            node = node->next;
            continue;
        }
        
        if (!user) {
            remove_node = TRUE;
        } else if (!xmlStrcasecmp ((xmlChar *) user, u)) {
            remove_node = TRUE;
        } else {
            other_entries = TRUE;
        }

        xmlFree (u);
        xmlFree (t);
        next_node = node->next;

        if (remove_node) {
            xmlUnlinkNode (node);
            xmlFreeNode (node);
        }
        
        node = next_node;
    }

    ok = write_xml_config (doc);
    xmlFreeDoc (doc);
    
    if (ok == -1) {
        return FALSE;
    } else if (other_entries) {
        return TRUE;
    } else {
        return run_pam_config (PAM_CONFIG_TYPE_CRYPTPASS_PASSWD, PAM_CONFIG_OP_REMOVE) &&
               run_pam_config (PAM_CONFIG_TYPE_CRYPTPASS, PAM_CONFIG_OP_REMOVE) && 
               run_pam_config (PAM_CONFIG_TYPE_MOUNT, PAM_CONFIG_OP_REMOVE);
    }
}

/*
 * Add an entry to the pam_mount conf to enable mounting of encrypted home
 * dirs during login.
 */
gboolean enable_pam_mount (const char *user, const char *image, const char *key_file)
{
    struct passwd *ent;
    const char *up;
    char *curr_image, *curr_key;
    xmlDocPtr doc;
    xmlNodePtr root_node, node;
    int ok;
    char esc_user[BUFF_SIZE];

    if (!g_file_test (image, G_FILE_TEST_EXISTS) ||
        !g_file_test (key_file, G_FILE_TEST_EXISTS)) {
        g_printerr ("access: %s\n", strerror (errno));
        return FALSE;
    }

    ent = getpwnam (user);
    if (!ent) {
        fprintf (stderr, "Failed to lookup user '%s'\n", user);
        return FALSE;
    }

    up = user;

    /* escaping '\' for AD users is required by pam_mount */
    if (strchr (user, '\\')) {
        int ui = 0, ei = 0;

        for (; user[ui] != '\0'; ui++, ei++) {
            if (user[ui] == '\\') {
                esc_user[ei] = '\\';
                ei++;
            }

            esc_user[ei] = user[ui];
        }

        up = esc_user;
    }

    /* see if we're already setup for this {user, image, key} */
    if (pam_mount_is_setup_for_user (up, &curr_image, &curr_key, NULL)) {
        if (!strcmp (image, curr_image) && !strcmp (key_file, curr_key)) {
            g_free (curr_image);
            g_free (curr_key);
            return TRUE;
        } else {
            g_free (curr_image);
            g_free (curr_key);

            /* The current entry is different.  Replace it */
            if (!disable_pam_mount (up)) {
                g_printerr ("Failed to change pam_mount entry for %s\n", up);
                return FALSE;
            }
        }
    }

    doc = xmlParseFile (PAM_MOUNT_CONF);
    if (!doc) {
        g_printerr ("Failed to read %s\n", PAM_MOUNT_CONF);
        return FALSE;
    }

    root_node = xmlDocGetRootElement (doc);
    if (!root_node) {
        g_printerr ("Failed to get root element from %s\n", PAM_MOUNT_CONF);
        return FALSE;
    }

    node = xmlNewChild (root_node, NULL, (xmlChar *) "volume", NULL);
    xmlNewProp (node, (xmlChar *) "fstype", (xmlChar *) "crypt");
    xmlNewProp (node, (xmlChar *) "user", (xmlChar *) up);
    xmlNewProp (node, (xmlChar *) "path", (xmlChar *) image);
    xmlNewProp (node, (xmlChar *) "fskeypath", (xmlChar *) key_file);
    xmlNewProp (node, (xmlChar *) "fskeycipher", (xmlChar *) "aes-256-cbc");
    xmlNewProp (node, (xmlChar *) "fskeyhash", (xmlChar *) "md5");
    xmlNewProp (node, (xmlChar *) "cipher", (xmlChar *) "aes-cbc-essiv:sha256");
    xmlNewProp (node, (xmlChar *) "options", (xmlChar *) "loop");
    xmlNewProp (node, (xmlChar *) "mountpoint", (xmlChar *) ent->pw_dir);
    xmlAddChild (root_node, node);
    ok = write_xml_config (doc);
    xmlFreeDoc (doc);

    if (ok == -1)
        return FALSE;
    else
        return run_pam_config (PAM_CONFIG_TYPE_MOUNT, PAM_CONFIG_OP_ADD) &&
               run_pam_config (PAM_CONFIG_TYPE_CRYPTPASS, PAM_CONFIG_OP_ADD) && 
               run_pam_config (PAM_CONFIG_TYPE_CRYPTPASS_PASSWD, PAM_CONFIG_OP_ADD);
}

/*
 * Get a passphrase from standard in.  If the verify flag is set then we prompt
 * the user again.  We also turn off echo if STDIN is a terminal.  The returned
 * passphrase will also be mlocked.  The passpharse field needs to be unlocked
 * and freed if the call returns TRUE.
 */
gboolean get_passphrase (const char *prompt, gboolean verify, gchar **passphrase) 
{
    char *p;
    int len, tty;
    ssize_t p1_len = 0, p2_len = 0, n;
    struct termios normal, no_echo;
    char buff[BUFF_SIZE];

    tty = isatty (STDIN_FILENO);
    if (tty) {
        if (tcgetattr (STDIN_FILENO, &normal)) {
            return FALSE;
        } else {
            no_echo = normal;
            no_echo.c_lflag &= ~ECHO;
        }
    }
    
    buff[BUFF_SIZE - 1] = '\0';
    len = snprintf (buff, BUFF_SIZE - 1, "%s: ", prompt);
    if (len == -1)
        return FALSE;

    if (write (STDOUT_FILENO, buff, len) == -1)
        return FALSE;

    *passphrase = g_malloc (BUFF_SIZE);
    if (!*passphrase)
        return FALSE;

    if (tty)
        tcsetattr (STDIN_FILENO, TCSAFLUSH, &no_echo);

    mlock (*passphrase, BUFF_SIZE);
    (*passphrase)[BUFF_SIZE - 1] = '\0';

    for (p = *passphrase; p1_len < BUFF_SIZE - 1; p++, p1_len++) {
        n = read (STDIN_FILENO, p, 1);
        if (n == -1) {
            goto error;
        } else if (n == 0 || *p == '\n') {
            *p = '\0';
            break;
        }
    }
    
    if (verify) {
        char passphrase2[BUFF_SIZE];
        
        buff[BUFF_SIZE - 1] = '\0';
        len = snprintf (buff, BUFF_SIZE - 1, "\n%s, again: ", prompt);
        if (len == -1)
            goto error;
        
        if (write (STDOUT_FILENO, buff, len) == -1)
            goto error;

        passphrase2[BUFF_SIZE - 1] = '\0';
        for (p = passphrase2; p2_len < BUFF_SIZE - 1; p++, p2_len++) {
            n = read (STDIN_FILENO, p, 1);
            if (n == -1) {
                goto error;
            } else if (n == 0 || *p == '\n') {
                *p = '\0';
                break;
            }
        }
        
        if (p1_len != p2_len || strncmp (*passphrase, passphrase2, p1_len))
            goto error;
    }

    if (tty)
        tcsetattr (STDIN_FILENO, TCSAFLUSH, &normal);

    if (write (STDOUT_FILENO, "\n", 1) == -1)
        goto error;

    return TRUE;

error:
    memset (*passphrase, 0, BUFF_SIZE);
    munlock (*passphrase, BUFF_SIZE);
    g_free (*passphrase);
    *passphrase = NULL;
    if (tty)
        tcsetattr (STDIN_FILENO, TCSAFLUSH, &normal);
    return FALSE;
}

/*
 * Enlarge our disk image by seeking past the end of the file and writing
 * a zero byte.
 */
gboolean enlarge_image (const char *image, guint64 size_to_add_in_mb)
{
    off64_t total = size_to_add_in_mb * 1048576;
    int fd = open (image, O_WRONLY | O_LARGEFILE);
    if (fd == -1) {
        g_printerr ("open: %s\n", strerror (errno));
        return FALSE;
    }

    if (flock (fd, LOCK_EX)) {
        g_printerr ("flock: %s\n", strerror (errno));
        close (fd);
        return FALSE;
    }

    if (lseek64 (fd, total, SEEK_END) == -1) {
        close (fd);
        return FALSE;
    }

    if (write (fd, "\0", 1) == -1) {
        g_printerr ("write: %s\n", strerror (errno));
        close (fd);
        return FALSE;
    }

    close (fd);
    return TRUE;
}

/*
 * Get random data for our new key.  key_data needs to  be
 * unlocked and freed by the caller.
 */
gboolean get_random_key_data (gchar **key_data, size_t key_size)
{
    int i, fd = open ("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        g_printerr ("open: %s\n", strerror (errno));
        return FALSE;
    }

    *key_data = g_malloc (key_size);
    mlock (*key_data, key_size);

    if (read (fd, *key_data, key_size) != key_size) {
        munlock (*key_data, key_size);
        g_free (*key_data);
        *key_data = NULL;
        close (fd);
        return FALSE;
    }

    /*
     * Make sure the data doesn't contain a new line
     * since cryptsetup stops reading the password if
     * it encounters one.
     */
    for (i = 0; i < key_size; i++) {
        if ((*key_data)[i] == '\n')
            (*key_data)[i] = '\0';
    }

    close (fd);
    return TRUE;
}

/*
 * Copy data in src to dest.  This function should not be called with
 * user input.
 */
gboolean copy_user_data (const char *home_dir, const char *dest)
{
    const gchar *file = NULL;
    GError *dir_err = NULL;
    GDir *dir = NULL;

    dir = g_dir_open (home_dir, 0, &dir_err);
    if (!dir) {
        g_printerr (_("g_dir_open: %s\n"), dir_err->message);
        g_error_free (dir_err);
        return FALSE;
    }
    
    while ((file = g_dir_read_name (dir))) {
        gchar *src = g_strdup_printf ("%s/%s", home_dir, file);
        gchar *ds = g_strdup (dest);
        gchar *argv[] = { "/bin/cp", "-axp", src, ds, NULL };
        GError *err = NULL;
        gint status;
        
        gboolean ret = g_spawn_sync (NULL, argv, NULL,
                                     G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                                     NULL, NULL, NULL, NULL, &status, &err);
        g_free (src);
        g_free (ds);
        if (!ret || WEXITSTATUS (status) != 0) {
            g_printerr (_("copy failed: %s\n"), err->message);
            g_error_free (err);
            g_dir_close (dir);
            return FALSE;
        }
    }

    g_dir_close (dir);
    return TRUE;
}

/*
 * Mount device on a temporary directory.  The mount_point string needs
 * to be freed by the caller.
 */
gboolean temp_mount (char *fs_type, char *device, char **mount_point)
{
    *mount_point = g_build_filename (g_get_tmp_dir (), "tmp-mount-XXXXXX", NULL);
    if (!mkdtemp (*mount_point)) {
        g_free (*mount_point);
        return FALSE;
    }

    return mount_dev (fs_type, device, *mount_point);
}

/*
 * Mount device at mount_point.
 */
gboolean mount_dev (char *fs_type, char *device, char *mount_point)
{
    int status;
    char *argv[] = { "/bin/mount", "-n", "-t", fs_type, "-o", "user_xattr", "--",
                     device, mount_point, NULL};
    return g_spawn_sync (NULL, argv, NULL,
                         G_SPAWN_STDOUT_TO_DEV_NULL,
                         NULL, NULL, NULL, NULL, &status, NULL); 
}

/*
 * Return TRUE if device is mounted.
 */
gboolean is_mounted (const char *dev)
{
    FILE *fp;
    char buff[BUFF_SIZE];
    
    fp = fopen ("/proc/mounts", "r");
    if (!fp) {
        g_printerr ("open: %s\n", strerror (errno));
        return FALSE;
    }

    while (fgets (buff, BUFF_SIZE, fp)) {
        if (strstr (buff, dev)) {
            fclose (fp);
            return TRUE;
        }
    }

    fclose (fp);
    return FALSE;
}

/*
 * If device is mounted then get the mount point.  The 
 * returned mount point should be freed by the caller.
 */
gboolean get_mount_point (const char *dev, char **mp)
{
    FILE *fp;
    char buff[BUFF_SIZE];
    
    fp = fopen ("/proc/mounts", "r");
    if (!fp) {
        g_printerr ("open: %s\n", strerror (errno));
        return FALSE;
    }

    while (fgets (buff, BUFF_SIZE, fp)) {
        if (strstr (buff, dev)) {
            gchar **fields = g_strsplit (buff, " ", -1);
            *mp = g_strdup (fields[1]);
            g_strfreev (fields);
            fclose (fp);
            return TRUE;
        }
    }

    fclose (fp);
    return FALSE;
}

/*
 * Resize the file system on a device.  Use tune2fs and debugreisefs
 * to detect the fs type.
 */
gboolean resize_filesystem (char *device)
{
    gchar *tune2fs_argv[] = { "/sbin/tune2fs", "-l", device, NULL };
    gchar *e2fsck_argv[] = { "/sbin/e2fsck", "-fp", device, NULL };
    gchar *resize2fs_argv[] = { "/sbin/resize2fs", device, NULL };
    gchar *debugreiser_argv[] = { "/sbin/debugreiserfs", device, NULL };
    gchar *reiserfsck_argv[] = { "/sbin/reiserfsck", "-y", device, NULL };
    gchar *resize_reiser_argv[] = { "/sbin/resize_reiserfs", device, NULL };
    int status;
    gboolean ret;

    /* ext2 and ext3 */
    ret = g_spawn_sync (NULL, tune2fs_argv, NULL,
                        G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                        NULL, NULL, NULL, NULL, &status, NULL);
    if (ret && WEXITSTATUS (status) == 0) {
        ret = g_spawn_sync (NULL, e2fsck_argv, NULL,
                            G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                            NULL, NULL, NULL, NULL, &status, NULL);
        if (!ret || WEXITSTATUS (status) != 0)
            return FALSE;

        ret = g_spawn_sync (NULL, resize2fs_argv, NULL,
                            G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                            NULL, NULL, NULL, NULL, &status, NULL);
        if (!ret || WEXITSTATUS (status) != 0)
            return FALSE;
        return TRUE;
    }

    /* reiser */
    ret = g_spawn_sync (NULL, debugreiser_argv, NULL,
                        G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                        NULL, NULL, NULL, NULL, &status, NULL);
    if (ret && WEXITSTATUS (status) == 0) {
        ret = g_spawn_sync (NULL, reiserfsck_argv, NULL,
                            G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                            NULL, NULL, NULL, NULL, &status, NULL);
        if (!ret || WEXITSTATUS (status) != 0)
            return FALSE;

        ret = g_spawn_sync (NULL, resize_reiser_argv, NULL,
                            G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                            NULL, NULL, NULL, NULL, &status, NULL);
        if (!ret || WEXITSTATUS (status) != 0)
            return FALSE;
        
        return TRUE;
    }

    return FALSE;
}

/*
 * Take a filesystem path and create a map device name.
 * The returned string must be freed by the caller.
 */
gchar *path_to_map_name (const char *path)
{
    gchar *p, *ret;
   
    if (!g_path_is_absolute (path)) {
        char *ap = realpath (path, NULL);
        if (!ap) {
            g_printerr ("realpath: %s\n", strerror (errno));
            return NULL;
        }

        ret = g_strdup (ap);
        free (ap);
    } else {
        ret = g_strdup (path);
    }

    for (p = ret; *p != '\0'; p++) {
        if (*p == '/' || *p == ' ')
            *p = '_';
    }

    return ret;
}

/*
 * Unlock image_file using key_file.  If key_file is NULL then we assume
 * we're using an image password.  If TRUE is returned then map_device and
 * loop_device needs to be freed by the caller.
 */
gboolean unlock_image (const char *image_file, const char *key_file,
                       char **map_device, char **loop_device)
{
    gchar *map_name = NULL, *map_dev = NULL, *password = NULL, *imgf = NULL;
    gchar *pass = NULL, *key_data = NULL, *prompt = NULL, *loop_dev = NULL;
    int pass_len, key_data_size;
    gboolean ret = FALSE;

    map_name = path_to_map_name (image_file);
    if (!map_name) {
        g_printerr (_("Failed to create map name\n"));
        goto cleanup;
    }

    map_dev = g_build_filename ("/dev/mapper", map_name, NULL);
    if (g_file_test (map_dev, G_FILE_TEST_EXISTS)) {
        g_printerr (_("The map device for this image is in use\n"));
        goto cleanup;
    }

    prompt = key_file ? _("Enter the key file password") : _("Enter the image password");
    if (!get_passphrase (prompt, FALSE, &password)) {
        g_printerr (_("Failed to get password\n"));
        goto cleanup;
    }
    
    /* if --key-file was given then decrypt the fs key */
    if (key_file) {
        if (g_access (key_file, F_OK | R_OK)) {
            g_printerr (_("Unable to access the specified key file\n"));
            goto cleanup;
        }
            
        if (!decrypt_key (key_file, password, &key_data, &key_data_size)) {
            g_printerr (_("Failed to decrypt key file with the provided password\n"));
            goto cleanup;
        }
    }

    pass = key_file ? key_data : password;
    pass_len = key_file ? key_data_size : strlen (password);

    /* setup our loop device */
    imgf = g_strdup (image_file);
    if (!loop_open (imgf, &loop_dev)) {
        g_printerr (_("Failed to open disk image\n"));
        goto cleanup;
    }

    /* unlock the device */
    if (!luks_open (pass, pass_len, loop_dev, map_name)) {
        g_printerr (_("Failed to open device\n"));
        goto cleanup;
    }

    *map_device = g_strdup (map_dev);
    *loop_device = g_strdup (loop_dev);
    ret = TRUE;

cleanup:
    if (key_data) {
        memset (key_data, 0, key_data_size);
        munlock (key_data, key_data_size);
    }

    if (password) {
        memset (password, 0, strlen (password));
        munlock (password, strlen (password));
    }

    g_free (password);
    g_free (map_name);
    g_free (map_dev);
    g_free (loop_dev);
    g_free (key_data);
    g_free (imgf);
    return ret;
}

/*
 * Decrypt an existing key file and add its contents to the LUKS device.
 */
gboolean add_key_file_to_device (char *device, char *extra_key_file,
                                 char *curr_key, long curr_key_len)
{
    gchar *extra_key_data = NULL, *extra_pass = NULL;
    gboolean ret = FALSE;
    int extra_key_size;
     
    if (!g_file_test (extra_key_file, G_FILE_TEST_EXISTS)) {
        g_printerr (_("Extra key file does not exist\n"));
        return FALSE;
    }

    if (!get_passphrase (_("\nEnter the password for the extra key"),
                         FALSE, &extra_pass)) {
        g_printerr (_("Failed to get extra key password\n"));
        return FALSE;
    }

    g_print ("\n");

    if (!decrypt_key (extra_key_file, extra_pass, &extra_key_data, &extra_key_size)) {
        g_printerr (_("Failed to decrypt extra key\n"));
        goto cleanup;
    }

    if (!luks_add_key (device, curr_key, curr_key_len, extra_key_data, extra_key_size)) {
        g_printerr (_("Failed to add extra key\n"));
        goto cleanup;
    }

    ret = TRUE;

cleanup:
    if (extra_key_data) {
        memset (extra_key_data, 0, extra_key_size);
        munlock (extra_key_data, extra_key_size);
    }
    
    if (extra_pass) {
        memset (extra_pass, 0, strlen (extra_pass));
        munlock (extra_pass, strlen (extra_pass));
    }
    
    g_free (extra_pass);
    g_free (extra_key_data);
    return ret;
}

/*
 *  Remove a user's home directory.
 */
gboolean remove_home_directory (struct passwd *pent)
{
    gchar *argv[] = { "/bin/rm", "-rf", pent->pw_dir, NULL };
    GError *err;
    gint status;
    gboolean ret;
    
    ret = g_spawn_sync (NULL, argv, NULL,
                        G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                        NULL, NULL, NULL, NULL, &status, &err);
    if (!ret) {
        g_printerr ("%s\n", err->message);
        g_error_free (err);
        return FALSE;
    }
    
    return WEXITSTATUS (status) ? FALSE : TRUE;
}

/*
 * Remove a directory tree.
 */
static gboolean remove_tree (char *tree)
{
    gchar *argv[] = { "/bin/rm", "-rf", tree, NULL };
    GError *err;
    gint status;
    gboolean ret;
    
    ret = g_spawn_sync (NULL, argv, NULL,
                        G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                        NULL, NULL, NULL, NULL, &status, &err);
    if (!ret) {
        g_printerr ("%s\n", err->message);
        g_error_free (err);
        return FALSE;
    }
    
    return WEXITSTATUS (status) ? FALSE : TRUE;
}

/*
 * Parse arg and set size to arg in MB.
 */
gboolean parse_size (const char *arg, gint64 *size)
{
    int m;
    gint64 s = 0;
    char unit = '\0';

    m = sscanf (arg, "%lld%c", &s, &unit);
    if (!m || s <= 0)
        return FALSE;

    switch (unit) {
    case '\0':
    case 'M':
        *size = s;
        return TRUE;
    case 'G':
        *size = s * 1024;
        break;
    case 'K':
        *size = s / 1024;
    default:
        return FALSE;
    }
    
    return TRUE;
}

/*
 * Create a directory to store data that will be publicly available.
 * The result parameter will point to the public data root and should
 * be freed by the caller.
 */
static gboolean create_public_directory (const char *user, gchar **result)
{
    struct passwd *pent;
    gchar *pub_dir = NULL, *dir = NULL, *base = NULL;
    gboolean ret = FALSE;

    pent = getpwnam (user);
    if (!pent) {
        g_printerr ("Failed to look up '%s'\n", user);
        return FALSE;
    }

    dir = g_path_get_dirname (pent->pw_dir);
    base = g_path_get_basename (pent->pw_dir);
    pub_dir = g_strdup_printf ("%s%s.%s", dir, G_DIR_SEPARATOR_S, base);

    if (g_mkdir_with_parents (pub_dir, 0755)) {
        g_printerr ("Failed to create public directory '%s'\n", pub_dir);
        goto cleanup;
    }
    
    if (chown (pub_dir, pent->pw_uid, pent->pw_gid)) {
        g_printerr ("Failed to chown public directory for %s\n", user);
        goto cleanup;
    }

    if (chmod (pub_dir, 0755)) {
        g_printerr ("Failed to chmod public directory for %s\n", user);
        goto cleanup;
    }

    if (result)
        *result = g_strdup (pub_dir);

    ret = TRUE;

cleanup:
    g_free (pub_dir);
    g_free (dir);
    g_free (base);
    return ret;
}

/*
 * Adjust the permissions of the components in target to match the ones in source.
 */
static gboolean adjust_path_permissions (const char *source_root, const char *target_root, const char *path)
{
    int i;
    gchar **parts = g_strsplit (path, "/", -1);
    gchar *source_path = g_strdup (source_root);
    gchar *target_path = g_strdup (target_root);
    gboolean ret = FALSE;

    for (i = 0; parts[i]; i++) {
        struct stat s_info;
        gchar *s_tmp = g_build_filename (source_path, parts[i], NULL);
        gchar *t_tmp = g_build_filename (target_path, parts[i], NULL);

        g_free (source_path);
        g_free (target_path);
        source_path = s_tmp;
        target_path = t_tmp;

        if (stat (source_path, &s_info)) {
            g_printerr ("Failed to stat %s: %s\n", source_path, strerror (errno));
            goto cleanup;
        }

        if (chmod (target_path, s_info.st_mode) ||
            chown (target_path, s_info.st_uid, s_info.st_gid)) {
            g_printerr ("Failed to modify %s: %s\n", target_path, strerror (errno));
            goto cleanup;
        }
    }

    ret = TRUE;

cleanup:
    g_free (source_path);
    g_free (target_path);
    g_strfreev (parts);
    return ret;
}

/*
 * Return a relative path rooted in 'root'. rel_path needs to be freed by the caller.
 */
static gboolean get_relative_path_with_root (const char *path, const char *root, gchar **rel_path)
{
    size_t len;

    if (g_path_is_absolute (path)) {
        len = strlen (root);
        if (len + 1 >= strlen (path))
            return FALSE;

        if (!strncmp (path, root, len)) {
            *rel_path = g_strdup (path + len + 1);
        } else {
            return FALSE;
        }
    } else {
        *rel_path = g_strdup (path);
    }
    
    return TRUE;
}

/*
 * Add data to a user's public directory.  path can be absolute 
 * or relative to the user's encrypted home directory.
 */
gboolean add_public_data (const char *user, const char *normal_hd,
                          const char *enc_hd, const char *path)
{
    gchar *pub_dir = NULL, *pub_base_dir = NULL, *pub_file = NULL;
    gchar *normal_link = NULL, *normal_base_dir = NULL;
    gchar *src_file = NULL, *src_base_dir = NULL, *rel_path = NULL;
    struct stat info;
    gboolean ret = FALSE;

    /* create public directory */
    if (!create_public_directory (user, &pub_dir)) {
        g_printerr ("Failed to create public directory for user %s\n", user);
        goto cleanup;
    }
    
    if (!get_relative_path_with_root (path, normal_hd, &rel_path)) {
        g_printerr ("%s is an invalid path\n", path);
        goto cleanup;
    }
    
    src_file = g_build_filename (enc_hd, rel_path, NULL);
    src_base_dir = g_path_get_dirname (src_file);
    pub_file = g_build_filename (pub_dir, rel_path, NULL);
    pub_base_dir = g_path_get_dirname (pub_file);
    normal_link = g_build_filename (normal_hd, rel_path, NULL);
    normal_base_dir = g_path_get_dirname (normal_link);

    /* see if the public file exists already */
    if (g_file_test (pub_file, G_FILE_TEST_EXISTS)) {
        g_printerr ("The public file %s already exists.\n", pub_file);
        goto cleanup;
    }

    /* make sure the file exists in the encrypted directory */
    if (stat (src_file, &info)) {
        g_printerr ("Failed to stat %s: %s\n", src_file, strerror (errno));
        goto cleanup;
    }

    /* make sure that the file doesn't exist in the unencrypted home */
    if (g_file_test (normal_link, G_FILE_TEST_EXISTS)) {
        g_printerr ("%s already exists, unlinking...\n", normal_link);
        if (g_remove (normal_link)) {
            g_printerr ("Failed to unlink %s\n", normal_link);
            goto cleanup;
        }
    }

    /* make sure the file isn't a symlink */
    if (g_file_test (src_file, G_FILE_TEST_IS_SYMLINK)) {
        gchar *link_target = NULL;

        if ((link_target = g_file_read_link (src_file, NULL)) &&
            !strcmp (link_target, pub_file)) {
            g_printerr ("%s is a symlink that already points to %s\n", src_file, pub_file);
        } else {
            g_printerr ("%s is a symlink\n", src_file);
        }
        
        g_free (link_target);
        goto cleanup;
    }

    /* create the directory structure in the public and normal directories */
    if (g_mkdir_with_parents (pub_base_dir, 0755)) {
        g_printerr ("Failed to create %s\n", pub_base_dir);
        goto cleanup;
    }

    if (g_mkdir_with_parents (normal_base_dir, 0755)) {
        g_printerr ("Failed to create %s\n", normal_base_dir);
        goto cleanup;
    }
   
    /* move the file to the public directory */
    if (!move_file (src_file, pub_file)) {
        g_printerr ("Failed to move %s to %s\n", src_file, pub_file);
        goto cleanup;
    }

    if (chmod (pub_file, info.st_mode) ||
        chown (pub_file, info.st_uid, info.st_gid)) {
        g_printerr ("Failed to modify permissions for %s: %s\n", pub_file, strerror (errno));
        goto cleanup;
    }

    /* create the symlinks */
    if (symlink (pub_file, src_file)) {
        g_printerr ("Failed to create symlink '%s': %s\n", src_file, strerror (errno));
        goto cleanup;
    }
    
    if (symlink (pub_file, normal_link)) {
        g_printerr ("Failed to create symlink '%s': %s\n", normal_link, strerror (errno));
        goto cleanup;
    }
    
    if (chown (src_file, info.st_uid, info.st_gid) ||
        chown (pub_file, info.st_uid, info.st_gid))
        g_printerr ("Failed to chown symlinks\n");
    
    if (!adjust_path_permissions (enc_hd, pub_dir, rel_path)) {
        g_printerr ("Failed to adjust path permissions\n");
        goto cleanup;
    }
    
    if (!adjust_path_permissions (enc_hd, normal_hd, rel_path)) {
        g_printerr ("Failed to adjust path permissions\n");
        goto cleanup;
    }

    ret = TRUE;

cleanup:
    g_free (rel_path);
    g_free (pub_dir);
    g_free (src_file);
    g_free (src_base_dir);
    g_free (pub_file);
    g_free (pub_base_dir);
    g_free (normal_link);
    g_free (normal_base_dir);
    return ret;
}

/*
 * Moves path from the user's public directory back to their
 * encrypted home directory.
 */
gboolean remove_public_data (const char *user, const char *normal_hd,
                             const char *enc_hd, const char *path)
{
    gchar *pub_dir = NULL, *pub_file = NULL, *dir = NULL, *base = NULL;
    gchar *normal_link = NULL, *enc_link = NULL, *rel_path = NULL;
    gchar *normal_tree = NULL, *pub_tree = NULL;
    gchar **pub_parts = NULL, **normal_parts = NULL;
    gboolean ret = FALSE;

    /* build the public directory name */
    dir = g_path_get_dirname (normal_hd);
    base = g_path_get_basename (normal_hd);
    pub_dir = g_strdup_printf ("%s/.%s", dir, base);
    g_free (dir);
    g_free (base);
    
    if (!get_relative_path_with_root (path, pub_dir, &rel_path)) {
        g_printerr ("%s is an invalid path\n", path);
        goto cleanup;
    }

    enc_link = g_build_filename (enc_hd, rel_path, NULL);
    pub_file = g_build_filename (pub_dir, rel_path, NULL);
    normal_link = g_build_filename (normal_hd, rel_path, NULL);

    /* make sure the public file exists */
    if (!g_file_test (pub_file, G_FILE_TEST_EXISTS)) {
        g_printerr ("The public file %s does not exist.\n", pub_file);
        goto cleanup;
    }

    /* remove the symlinks */
    if (g_file_test (normal_link, G_FILE_TEST_IS_SYMLINK) &&
        g_remove (normal_link)) {
        g_printerr ("Failed to remove %s\n", normal_link);
        goto cleanup;
    }

    if (g_file_test (enc_link, G_FILE_TEST_IS_SYMLINK) &&
        g_remove (enc_link)) {
        g_printerr ("Failed to remove %s\n", normal_link);
        goto cleanup;
    }

    /* move the public file to the encrypted home */
    if (!move_file (pub_file, enc_link)) {
        g_printerr ("Failed to move %s to %s\n", pub_file, enc_link);
        goto cleanup;
    }

    /* remove public and normal trees */
    dir = g_path_get_dirname (pub_file);
    if (strcmp (dir, pub_dir)) {
        /* directories need to be removed */
        pub_parts = g_strsplit (pub_file + strlen (pub_dir) + 1, "/", -1);
        pub_tree = g_build_filename (pub_dir, pub_parts[0], NULL); 
        normal_parts = g_strsplit (normal_link + strlen (normal_hd) + 1, "/", -1);
        normal_tree = g_build_filename (normal_hd, normal_parts[0], NULL); 
        
        if (!remove_tree (pub_tree))
            g_printerr ("Failed to remove %s\n", pub_tree);

        if (!remove_tree (normal_tree))
            g_printerr ("Failed to remove %s\n", normal_tree);
    }
    
    g_free (dir);
    ret = TRUE;

cleanup:
    g_free (rel_path);
    g_free (enc_link);
    g_free (pub_dir);
    g_free (pub_file);
    g_free (normal_link);
    g_free (pub_tree);
    g_free (normal_tree);
    g_strfreev (pub_parts);
    g_strfreev (normal_parts);
    return ret;
}
