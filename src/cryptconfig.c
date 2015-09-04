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
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "cryptconfig.h"

typedef struct _command {
    gchar *name;
    gchar *arguments;
    gchar *description;
    gboolean (*execute) (char *cmd, int argc, char *argv[]);
    gboolean requires_root;
} Command;

static GHashTable *commands = NULL;

/*
 * Show command help with the correct usage line
 */
static void show_command_help (GOptionContext *ctx, const char *cmd, char *argv[])
{
    int argc = 2;
    argv[0] = g_strdup_printf ("%s %s", argv[0], cmd);
    argv[1] = "--help";
    g_option_context_parse (ctx, &argc, &argv, NULL);
    g_option_context_free (ctx);
    exit (1);
}

/*
 * This is the command to create a new encrypted home directory image and key
 */
static gboolean command_make_encrypted_home (char *cmd, int argc, char *argv[])
{
    GError *err = NULL;
    GOptionContext *ctx;
    gboolean ret, no_verify = FALSE, no_pam_mount = FALSE, final_ret = FALSE, unlink_old_home = FALSE;
    gboolean random_data = FALSE, no_copy = FALSE, force = FALSE, replace = FALSE;
    gchar *key_file = NULL, *image_file = NULL, *existing_key_file = NULL;
    gchar *fs_type = "ext3", *pass = NULL, *loop_device = NULL;
    gchar *key_data = NULL, *map_dev = NULL, *temp_dir = NULL;
    gchar *user_field, *prompt = NULL, *extra_key_file = NULL; 
    int key_size = KEY_DATA_SIZE;
    gint64 image_size, req_fs_size;
    struct passwd *pent;

    GOptionEntry entries[] = {
        { "no-verify", 0, 0, G_OPTION_ARG_NONE, &no_verify, N_("Don't verify the passphrase"), NULL },
        { "no-pam-mount", 0, 0, G_OPTION_ARG_NONE, &no_pam_mount, N_("Don't setup pam_mount"), NULL },
        { "no-copy", 0, 0, G_OPTION_ARG_NONE, &no_copy, N_("Don't copy user's existing data"), NULL },
        { "random", 0, 0, G_OPTION_ARG_NONE, &random_data, N_("Use random data to fill the image"), NULL },
        { "force", 0, 0, G_OPTION_ARG_NONE, &force, N_("Overwrite existing image and key"), NULL },
        { "remove-data", 0, 0, G_OPTION_ARG_NONE, &unlink_old_home, N_("Remove the old home "
                                                                       "directory after data is copied"), NULL },
        { "replace", 0, 0, G_OPTION_ARG_NONE, &replace, N_("Replace an existing user entry in pam_mount"), NULL },
        { "fs-type", 0, 0, G_OPTION_ARG_STRING, &fs_type, N_("The filesystem type. The default is ext3"), NULL },
        { "image-file", 0, 0, G_OPTION_ARG_STRING, &image_file,
          N_("The home directory image. The default is $USER_HOME.img"), NULL },
        { "key-file", 0, 0, G_OPTION_ARG_STRING, &key_file,
          N_("The image key file. The default is $USER_HOME.key"), NULL },
        { "existing-key-file", 0, 0, G_OPTION_ARG_STRING, &existing_key_file,
          N_("Use an existing key file instead of generating a new one"), NULL },
        { "extra-key-file", 0, 0, G_OPTION_ARG_STRING, &extra_key_file,
          N_("Add an additional key file to the image"), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    /* parse our options for this command */
    ctx = g_option_context_new ("user size_in_mb");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr ("parsing failed: %s\n", err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != 4)
        show_command_help (ctx, cmd, argv);

    user_field = argv[2];
    g_option_context_free (ctx);

    /* don't allow encrypted home directories for root */
    if (!strncmp (user_field, "root", 4) && strlen (user_field) == 4) {
        g_printerr (_("Using an encrypted home directory for root is not supported\n"));
        return FALSE;
    }

    /* make sure we're using a valid fs_type */
    if (!is_filesystem_supported (fs_type)) {
        gchar *fs = get_supported_filesystems (); 
        g_printerr (_("%s is not a supported file system\nSupported file "
                    "systems are: %s\n"), fs_type, fs);
        g_free (fs);
        return FALSE;
    }
    
    /* validate image size */
    if (!parse_size (argv[3], &image_size)) {
        g_printerr (_("Invalid image size\n"));
        return FALSE;
    }

    /* check image size against the min fs size */
    if (!check_min_fs_size (fs_type, image_size, &req_fs_size)) {
        g_printerr (_("The image_size must be at least %lld MBs for the "
                      "chosen file system.\n"), req_fs_size);
        return FALSE;
    }

    /* lookup the user in the password file */
    pent = getpwnam (user_field);
    if (!pent) {
        g_printerr (_("Failed to lookup user '%s'\n"), user_field);
        return FALSE;
    }

    /* make sure pam_mount is not configured for this user already */
    if (pam_mount_is_setup_for_user (user_field, NULL, NULL, NULL)) {
        if (!replace) {
            g_printerr (_("pam_mount is already setup for %s.  "
                        "Use --replace to replace the existing entry\n"), user_field);
            return FALSE;
        } else {
            if (!disable_pam_mount (user_field)) {
                g_printerr (_("Failed to remove old pam_mount entry\n"));
                return FALSE;
            }
        }
    }

    /* set image_file */
    if (!image_file) {
        image_file = g_strdup_printf ("%s.img", pent->pw_dir);
    } else {
        gchar *image_dir;

        image_file = g_strdup (image_file);
        if (!g_path_is_absolute (image_file)) {
            g_printerr (_("image file must be an absolute path\n"));
            goto cleanup;
        }

        /* make sure image_dir exists */
        image_dir = g_path_get_dirname (image_file);
        if (!g_file_test (image_dir, G_FILE_TEST_IS_DIR)) {
            g_printerr (_("'%s' is not a directory\n"), image_dir);
            g_free (image_dir);
            goto cleanup;
        }

        /* make sure there's enough space on the disk */
        if (!check_requested_space (image_dir, image_size)) {
            g_printerr (_("Not enough space to create %s\n"), image_file);
            g_free (image_dir);
            goto cleanup;
        }

        g_free (image_dir);
    }

    /* if --force wasn't provided then we fail if image_file exists */
    if (!force && g_file_test (image_file, G_FILE_TEST_EXISTS)) {
        g_printerr (_("%s already exists.  Use --force to overwrite it.\n"), image_file);
        goto cleanup;
    }

    if (existing_key_file) {
        /* an existing key file was given. don't generate one */
        if (key_file) {
            g_printerr (_("You can't specify both --key-file and --existing-key-file\n"));
            goto cleanup;
        }
       
        if (!g_path_is_absolute (existing_key_file)) {
            g_printerr (_("The existing key file must be an absolute path\n"));
            goto cleanup;
        }

        if (!g_file_test (existing_key_file, G_FILE_TEST_EXISTS)) {
            g_printerr (_("%s does not exist\n"), existing_key_file);
            goto cleanup;
        }
    } else if (!key_file) {
        /* we need to create a key in the default location */
        key_file = g_strdup_printf ("%s.key", pent->pw_dir);
    } else {
        /* a key file location was given.  make sure the directory exists */
        gchar *dn;
        gboolean ex;
    
        if (!g_path_is_absolute (key_file)) {
            g_printerr (_("The key file must be an absolute path\n"));
            goto cleanup;
        }

        dn = g_path_get_dirname (key_file);
        ex = g_file_test (dn, G_FILE_TEST_IS_DIR);
        g_free (dn);
        
        if (!ex) {
            g_printerr (_("The key file directory does not exist\n"));
            goto cleanup;
        }
    }

    /* if --force wasn't provided then we fail if key_file exists */
    if (!force && key_file && g_file_test (key_file, G_FILE_TEST_EXISTS)) {
        g_printerr (_("'%s' already exists.  Use --force to overwrite it.\n"), key_file);
        goto cleanup;
    }

    /* disable data copying if the user's home dir doesn't exist */
    if (!g_file_test (pent->pw_dir, G_FILE_TEST_IS_DIR)) {
        g_printerr (_("Skipping data copy since user's home directory does not exist\n"));
    } else if (!no_copy) {
        /*
         * Make sure we have enough disk space to copy the user's data and
         * that the encrypted image is large enough to hold the user's data.
         */
        guint64 home_size;
        if (!check_disk_space (image_file, pent->pw_dir, &home_size)) {
            g_printerr (_("There is not enough disk space left to copy existing data\n"));
            goto cleanup;
        }

        if (image_size < home_size) {
            g_printerr (_("The specified image size is not large enough to hold the user's data\n"));
            goto cleanup;
        }
    }

    prompt = existing_key_file ? g_strdup_printf (_("Enter the password for %s"), existing_key_file) :
                                 g_strdup_printf (_("Enter %s's password"), user_field);
    if (!get_passphrase (prompt, !no_verify, &pass)) {
        g_printerr (_("Failed to get password\n"));
        goto cleanup;
    }

    /* get key data from an existing key or generate it for new keys */
    if (existing_key_file) {
        if (!decrypt_key (existing_key_file, pass, &key_data, &key_size)) {
            g_printerr (_("Unable to decrypt %s with the supplied password\n"), existing_key_file);
            goto cleanup;
        }
    } else {
        if (!get_random_key_data (&key_data, key_size)) {
            g_printerr (_("Failed to get key data\n"));
            goto cleanup;
        }

        if (!encrypt_key (key_file, pass, key_data, key_size)) {
            g_printerr (_("Failed to create image key\n"));
            goto cleanup;
        }

        if (chown (key_file, pent->pw_uid, 0) ||
            chmod (key_file, 0600)) {
            g_printerr (_("Failed to set permissions for key file\n"));
            goto cleanup;
        }
    }

    /* create and set permissions for our new image */
    g_print (_("\nCreating disk image... "));
    ret = random_data ? create_image_random (image_file, image_size) :
                        create_image_zero (image_file, image_size);
    if (!ret) {
        g_printerr (_("\nFailed to create image\n"));
        goto cleanup;
    }

    g_print (_("Done\n"));
    
    if (chown (image_file, pent->pw_uid, 0) ||
        chmod (image_file, 0600)) {
        g_printerr (_("Failed to set permissions for new image\n"));
        goto cleanup;
    }

    /* open our image */
    if (!loop_open (image_file, &loop_device)) {
        g_printerr (_("Failed to open image\n"));
        goto cleanup;
    }

    /* setup our image */
    if (!luks_format (key_data, key_size, loop_device)) {
        g_printerr (_("Failed to format image\n"));
        goto cleanup;
    }

    /* get the extra key data and add it to the image if necessary */
    if (extra_key_file && !add_key_file_to_device (loop_device, extra_key_file,
                                                   key_data, key_size)) {
        g_printerr (_("Failed to add extra key\n"));
        goto cleanup;
    }

    if (!luks_open (key_data, key_size, loop_device, user_field)) {
        g_printerr (_("Failed to open image\n"));
        goto cleanup;
    }

    /* create a file system on the mapped device */
    map_dev = g_build_filename ("/dev/mapper", user_field, NULL);
    if (!create_filesystem (map_dev, fs_type)) {
        g_printerr (_("Failed to create filesystem.\n"));
        goto cleanup;
    }

    /* temporarily mount our image */
    if (!temp_mount (fs_type, map_dev, &temp_dir)) {
        g_printerr (_("Failed to mount image\n"));
        goto cleanup;
    }

    /* setup permissions for the new image root */
    if (chown (temp_dir, pent->pw_uid, pent->pw_gid)) {
        g_printerr (_("Failed to set new directory permissions\n"));
        goto cleanup;
    }

    /* copy the user's existing data */
    if (!no_copy) {
        g_print (_("Copying existing data from %s.  This may take some time... "), pent->pw_dir);
        if (!copy_user_data (pent->pw_dir, temp_dir)) {
            g_printerr (_("\nFailed to copy user data\n"));
            goto cleanup;
        } else if (unlink_old_home) {
            if (!remove_home_directory (pent)) {
                g_printerr ("\n%s\n", strerror (errno));
                goto cleanup;
            }

            if (mkdir (pent->pw_dir, 0755)) {
                g_printerr ("\nmkdir: %s\n", strerror (errno));
                goto cleanup;
            }
        }

        g_print (_("Done.\n"));
    }

    /* make root the owner of the unencrypted home directory */
    if (chown (pent->pw_dir, 0, 0) ||
        chmod (pent->pw_dir, 0755)) {
        g_printerr ("%s\n", strerror (errno));
        goto cleanup;
    }
    
    /* setup pam_mount unless told otherwise */
    if (!no_pam_mount && !enable_pam_mount (user_field, image_file,
                                            key_file ? key_file : existing_key_file)) {
        g_printerr (_("Failed to setup pam_mount\n"));
        goto cleanup;
    }

    final_ret = TRUE;

cleanup:
    if (key_data) {
        memset (key_data, 0, key_size);
        munlock (key_data, key_size);
    }
    
    if (pass) {
        memset (pass, 0, strlen (pass));
        munlock (pass, strlen (pass));
    }

    /* 
     * Clean up after ourselves.  Some of this stuff might fail,
     * but we can't do much about it at this point.
     */
    if (temp_dir)
        umount (temp_dir);
    if (g_file_test (map_dev, G_FILE_TEST_EXISTS))
        luks_close (map_dev);
    if (loop_device)
        loop_close (loop_device);
    
    g_free (image_file);
    g_free (pass);
    g_free (loop_device);
    g_free (key_data);
    g_free (map_dev);
    g_free (prompt);
    g_free (key_file);
    g_free (temp_dir);
    g_free (existing_key_file);
    return final_ret;
}

/*
 * Create a luks partition
 */
static gboolean command_make_luks_device (char *cmd, int argc, char *argv[])
{
    GError *err = NULL;
    GOptionContext *ctx;
    gchar *dev, *pass = NULL, *base = NULL, *map_dev = NULL, *fs_type = "ext3";
    gboolean ret, no_verify = FALSE, retval = FALSE;
    struct stat info;

    GOptionEntry entries[] = {
        { "no-verify", 0, 0, G_OPTION_ARG_NONE, &no_verify, N_("Don't verify the new password"), NULL },
        { "fs-type", 0, 0, G_OPTION_ARG_STRING, &fs_type, N_("The filesystem type, defaults to ext3"), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    ctx = g_option_context_new ("device");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != 3)
        show_command_help (ctx, cmd, argv);
   
    g_option_context_free (ctx);
    dev = argv[2];
   
    /* make sure the dev is a valid block device */
    if (g_stat (dev, &info) || !S_ISBLK (info.st_mode)) {
        g_printerr (_("%s is not a block device\n"), dev);
        return FALSE;
    }

    /* make sure the device isn't mounted */
    if (is_mounted (dev)) {
        g_printerr (_("%s is currently mounted\n"), dev);
        return FALSE;
    }

    /* make sure we're using a valid fs_type */
    if (!is_filesystem_supported (fs_type)) {
        gchar *fs = get_supported_filesystems (); 
        g_printerr (_("%s is not a supported file system\nSupported file "
                    "systems are: %s\n"), fs_type, fs);
        g_free (fs);
        return FALSE;
    }

    /* verify that the user wants to do this unless no-verify is passed */
    if (!no_verify) {
        char answer[4];

        g_print ("Are you sure you want to format %s (y/N)? ", dev);
        if (read (STDIN_FILENO, answer, 4) == -1)
            return FALSE;

        if (answer[0] != 'Y' && answer[0] != 'y')
            return FALSE;
    }

    /* get the password */
    if (!get_passphrase (_("Enter a password for the partition"), !no_verify, &pass)) {
        g_printerr (_("Failed to get password\n"));
        goto cleanup;
    }

    /* format the device */
    g_print (_("Formatting device... "));
    if (!luks_format (pass, strlen (pass), dev)) {
        g_printerr (_("\nFailed to format %s\n"), dev);
        goto cleanup;
    }

    g_print (_("Done.\n"));

    /* map the device */
    base = g_path_get_basename (dev);
    if (!luks_open (pass, strlen (pass), dev, base)) {
        g_printerr (_("Failed to open %s\n"), dev);
        goto cleanup;
    }

    /* create the filesystem */
    g_print (_("Creating file system on device...  "));
    map_dev = g_build_filename ("/dev/mapper", base, NULL);
    if (!create_filesystem (map_dev, fs_type)) {
        g_printerr (_("\nFailed to create filesystem.\n"));
        goto cleanup;
    }
   
    g_print (_("Done\n"));
    retval = TRUE;

cleanup:
    if (pass) {
        memset (pass, 0, strlen (pass));
        munlock (pass, strlen (pass));
    }
    
    if (g_file_test (map_dev, G_FILE_TEST_EXISTS))
        luks_close (map_dev);
        
    g_free (pass);
    g_free (base);
    g_free (map_dev);
    return retval;
}

/*
 * Create a LUKS disk image
 */
static gboolean command_create_luks_image (char *cmd, int argc, char *argv[])
{
    GError *err = NULL;
    GOptionContext *ctx;
    gchar *image_file, *fs_type = "ext3", *pass_new = NULL;
    gchar *loop_device = NULL, *map_name = NULL, *map_dev = NULL;
    gchar *key_data = NULL, *pass = NULL, *key_file = NULL, *prompt = NULL;
    gchar *extra_key_file = NULL, *existing_key_file = NULL, *image_dir = NULL;
    gboolean ret, random_data = FALSE, no_verify = FALSE, force = FALSE, retval = FALSE;
    gint64 image_size, req_fs_size;
    size_t pass_len;
    int key_size = KEY_DATA_SIZE;

    GOptionEntry entries[] = {
        { "no-verify", 0, 0, G_OPTION_ARG_NONE, &no_verify, N_("Don't verify the new password"), NULL },
        { "random", 0, 0, G_OPTION_ARG_NONE, &random_data, N_("Use random data to fill the image"), NULL },
        { "force", 0, 0, G_OPTION_ARG_NONE, &force, N_("Overwrite an existing image"), NULL },
        { "key-file", 0, 0, G_OPTION_ARG_STRING, &key_file, N_("The image key file"), NULL },
        { "fs-type", 0, 0, G_OPTION_ARG_STRING, &fs_type, N_("The file system type, defaults to ext3"), NULL },
        { "existing-key-file", 0, 0, G_OPTION_ARG_STRING, &existing_key_file,
          N_("Use an existing key file instead of generating a new one"), NULL },
        { "extra-key-file", 0, 0, G_OPTION_ARG_STRING, &extra_key_file,
          N_("Add an additional key file to the image"), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    ctx = g_option_context_new ("image_file size_in_mb");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != 4)
        show_command_help (ctx, cmd, argv);
    
    g_option_context_free (ctx);
    image_file = argv[2];
   
    /* validate our image size */
    if (!parse_size (argv[3], &image_size)) {
        g_printerr (_("Invalid image size\n"));
        return FALSE;
    }

    /* complain if the image exists */
    if (!force && g_file_test (image_file, G_FILE_TEST_EXISTS)) {
        g_printerr (_("%s already exists.  Use --force to overwrite.\n"), image_file);
        goto cleanup;
    }

    /* make sure we're using a valid fs_type */
    if (!is_filesystem_supported (fs_type)) {
        gchar *fs = get_supported_filesystems (); 
        g_printerr (_("%s is not a supported file system\nSupported file "
                    "systems are: %s\n"), fs_type, fs);
        g_free (fs);
        return FALSE;
    }

    /* check image size against the min fs size */
    if (!check_min_fs_size (fs_type, image_size, &req_fs_size)) {
        g_printerr (_("The image_size must be at least %lld MBs for the "
                      "chosen file system.\n"), req_fs_size);
        return FALSE;
    }

    /* make sure there's enough space on the disk */
    image_dir = g_path_get_dirname (image_file);
    if (!check_requested_space (image_dir, image_size)) {
        g_printerr (_("Not enough space to create %s\n"), image_file);
        goto cleanup;
    }

    /* display the correct prompt */
    if (existing_key_file) {
        prompt = _("Enter the password for the existing key file "); 
    } else if (key_file) {
        prompt = _("Enter a password to encrypt the key file with");
    } else {
        prompt = _("Enter the new image password");
    }

    if (!get_passphrase (prompt, !no_verify, &pass_new)) {
        g_printerr (_("Failed to get password\n"));
        goto cleanup;
    }

    if (existing_key_file) {
        /* an existing key file was given. don't generate one */
        if (key_file) {
            g_printerr (_("You can't specify both --key-file and --existing-key-file\n"));
            goto cleanup;
        }
       
        if (!g_path_is_absolute (existing_key_file)) {
            g_printerr (_("The existing key file must be an absolute path\n"));
            goto cleanup;
        }

        if (!g_file_test (existing_key_file, G_FILE_TEST_EXISTS)) {
            g_printerr (_("%s does not exist\n"), existing_key_file);
            goto cleanup;
        }

        if (!decrypt_key (existing_key_file, pass_new, &key_data, &key_size)) {
            g_printerr (_("Unable to decrypt %s with the supplied password\n"), existing_key_file);
            goto cleanup;
        }
        
        pass = key_data;
        pass_len = key_size;
    } else if (key_file) {
        /* we need to generate a new key file */
        if (!force && g_file_test (key_file, G_FILE_TEST_EXISTS)) {
            g_printerr (_("%s already exists.  Use --force to overwrite.\n"), key_file);
            goto cleanup;
        }

        if (!get_random_key_data (&key_data, key_size)) {
            g_printerr (_("Failed to read key data\n"));
            goto cleanup;
        }
        
        /* create our key and set it's permissions */
        if (!encrypt_key (key_file, pass_new, key_data, key_size) ||
            chmod (key_file, 0600)) {
            g_printerr (_("Failed to create image key\n"));
            goto cleanup;
        }
        
        pass = key_data;
        pass_len = key_size;
    } else {
        /* the image is just going to have a password */
        pass = pass_new;
        pass_len = strlen (pass_new);
    }
  
    /* create the image file and fill it with zeros or random data */
    g_print (_("\nCreating disk image... "));
    ret = random_data ? create_image_random (image_file, image_size) :
                        create_image_zero (image_file, image_size);
    if (!ret) {
        g_printerr (_("\nFailed to create image\n"));
        goto cleanup;
    }

    g_print (_("Done.\n"));

    /* mount the image */
    if (!loop_open (image_file, &loop_device)) {
        g_printerr (_("Failed to open image\n"));
        goto cleanup;
    }

    /* format the image */
    g_print (_("Creating LUKS header... "));
    if (!luks_format (pass, pass_len, loop_device)) {
        g_printerr (_("\nFailed to format device\n"));
        goto cleanup;
    }
    
    g_print (_("Done.\n"));
    
    /* get the extra key data and add it to the image if necessary */
    if (extra_key_file && !add_key_file_to_device (loop_device, extra_key_file,
                                                   pass, pass_len)) {
        g_printerr (_("Failed to add extra key\n"));
        goto cleanup;
    }

    /* unlock the device and create a file system */
    map_name = path_to_map_name (loop_device);
    if (!map_name) {
        g_printerr (_("Failed to create map name\n"));
        goto cleanup;
    }

    if (!luks_open (pass, pass_len, loop_device, map_name)) {
        g_printerr (_("Failed to open device\n"));
        goto cleanup;
    }

    map_dev = g_build_filename ("/dev/mapper", map_name, NULL); 
    if (!create_filesystem (map_dev, fs_type)) {
        g_printerr (_("Failed create file system on mapped device\n"));
        goto cleanup;
    }

    retval = TRUE;

cleanup:
    if (key_data) {
        memset (key_data, 0, key_size);
        munlock (key_data, key_size);
    }

    if (pass_new) {
        memset (pass_new, 0, strlen (pass_new));
        munlock (pass_new, strlen (pass_new));
    }
    
    if (g_file_test (map_dev, G_FILE_TEST_EXISTS))
        luks_close (map_name);
    if (loop_device)
        loop_close (loop_device);

    g_free (key_data);
    g_free (pass_new);
    g_free (loop_device);
    g_free (map_name);
    g_free (map_dev);
    g_free (extra_key_file);
    g_free (existing_key_file);
    g_free (image_dir);
    return retval;
}

/*
 * Enlarge our disk image and the file system on the image.
 */
static gboolean command_enlarge_image (char *cmd, int argc, char *argv[])
{
    gint64 size;
    GError *err = NULL;
    GOptionContext *ctx;
    gchar *loop_device = NULL, *key_file = NULL, *map_device = NULL;
    gboolean ret, retval = FALSE;

    GOptionEntry entries[] = {
        { "key-file", 0, 0, G_OPTION_ARG_STRING, &key_file, N_("The encrytped key for the image"), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    ctx = g_option_context_new ("image size_to_add_in_mb");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != 4)
        show_command_help (ctx, cmd, argv);

    g_option_context_free (ctx);
   
    /* validate size and image location */
    if (!parse_size (argv[3], &size)) {
        g_printerr (_("Invalid size\n"));
        return FALSE;
    }
    
    if (!g_file_test (argv[2], G_FILE_TEST_EXISTS)) {
        g_printerr (_("Image file '%s' does not exist\n"), argv[2]);
        return FALSE;
    }

    /* enlarge the actual image file */
    if (!enlarge_image (argv[2], size)) {
        g_printerr (_("Failed to resize image\n"));
        goto cleanup;
    }

    /* unlock the image */
    if (!unlock_image (argv[2], key_file, &map_device, &loop_device)) {
        g_printerr (_("Failed to unlock image\n"));
        goto cleanup;
    }

    /* resize the actualy file system */
    if (!resize_filesystem (map_device)) {
        g_printerr (_("Failed to resize the file system on %s\n"), map_device);
        goto cleanup;
    }

    retval = TRUE;
    g_print (_("Done.\n"));

cleanup:
    if (map_device && g_file_test (map_device, G_FILE_TEST_EXISTS))
        luks_close (map_device);
    if (loop_device)
        loop_close (loop_device);
    
    g_free (loop_device);
    g_free (map_device);
    return retval;
}

/*
 * Change the password used to encrypt/decrypt an image key
 */
static gboolean command_change_password (char *cmd, int argc, char *argv[])
{
    GError *err = NULL;
    GOptionContext *ctx;
    gchar *pass_old = NULL, *pass_new = NULL, *key_data = NULL;
    int key_size = 0;
    gboolean ret, no_verify = FALSE, retval = FALSE;
    struct stat info;

    GOptionEntry entries[] = {
        { "no-verify", 0, 0, G_OPTION_ARG_NONE, &no_verify, N_("Don't verify the new password"), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    ctx = g_option_context_new ("key_file");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != 3)
        show_command_help (ctx, cmd, argv);

    g_option_context_free (ctx);
  
    /* make sure the key exists */
    if (stat (argv[2], &info)) {
        g_printerr (_("Failed to stat '%s': %s\n"), argv[2], strerror (errno));
        return FALSE;
    }

    /* get both passwords */
    if (!get_passphrase (_("Enter the EXISTING password"), FALSE, &pass_old)) {
        g_printerr (_("Failed to get existing password\n"));
        return FALSE;
    }

    g_print ("\n");
    if (!get_passphrase (_("Enter the NEW password"), !no_verify, &pass_new)) {
        g_printerr (_("Failed to get new password\n"));
        goto cleanup;
    }
    
    /* decrypt and re-encrypt the key */
    g_print ("\n");
    if (!decrypt_key (argv[2], pass_old, &key_data, &key_size)) {
        g_printerr (_("Failed to decrypt key with old password.\n"));
        goto cleanup;
    }

    if (!encrypt_key (argv[2], pass_new, key_data, key_size)) {
        g_printerr (_("Failed to encrypt new key\n"));
        goto cleanup;
    }

    if (chown (argv[2], info.st_uid, 0) || chmod (argv[2], 0600)) {
        g_printerr (_("Failed to retain permissions for %s\n"), argv[2]);
        goto cleanup;
    }

    retval = TRUE;
    g_print (_("Done.\n"));

cleanup:
    if (key_data) {
        memset (key_data, 0, key_size);
        munlock (key_data, key_size);
    }

    if (pass_old) {
        memset (pass_old, 0, strlen (pass_old));
        munlock (pass_old, strlen (pass_old));
    }
    
    if (pass_new) {
        memset (pass_new, 0, strlen (pass_new));
        munlock (pass_new, strlen (pass_new));
    }

    g_free (pass_old);
    g_free (pass_new);
    g_free (key_data);
    return retval;
}

/*
 * Add an entry in pam_mount.conf for encrypted home dirs. 
 */
static gboolean command_enable_pam_mount (char *cmd, int argc, char *argv[])
{
    struct passwd *pent;
    GError *err = NULL;
    GOptionContext *ctx;
    gchar *image_file = NULL, *key_file = NULL;
    gboolean ret, retval = FALSE, replace = FALSE;

    GOptionEntry entries[] = {
        { "replace", 0, 0, G_OPTION_ARG_NONE, &replace, N_("Replace an existing user entry in pam_mount"), NULL },
        { "image-file", 0, 0, G_OPTION_ARG_STRING, &image_file,
          N_("The user's home image file, defaults to /home/$USER.img"), NULL },
        { "key-file", 0, 0, G_OPTION_ARG_STRING, &key_file,
          N_("The user's image key file, defaults to /home/$USER.key"), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    ctx = g_option_context_new ("user");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != 3)
        show_command_help (ctx, cmd, argv);

    g_option_context_free (ctx);

    /* lookup the user */
    pent = getpwnam (argv[2]);
    if (!pent) {
        g_printerr (_("Failed to lookup user %s\n"), argv[2]);
        return FALSE;
    }

    /* make sure pam_mount is not configured for this user already */
    if (pam_mount_is_setup_for_user (argv[2], NULL, NULL, NULL)) {
        if (!replace) {
            g_printerr (_("pam_mount is already setup for %s.  "
                        "Use --replace to replace the existing entry\n"), argv[2]);
            return FALSE;
        } else {
            if (!disable_pam_mount (argv[2])) {
                g_printerr (_("Failed to remove old pam_mount entry\n"));
                return FALSE;
            }
        }
    }

    /* set image file  */
    if (!image_file) {
        image_file = g_strdup_printf ("%s.img", pent->pw_dir); 
    } else {
        if (!g_path_is_absolute (image_file)) {
            g_printerr (_("The image file must be an absolute path\n"));
            goto cleanup;
        }
    }

    /* set key file */
    if (!key_file) {
        key_file = g_strdup_printf ("%s.key", pent->pw_dir);
    } else {
        if (!g_path_is_absolute (key_file)) {
            g_printerr (_("The key file must be an absolute path\n"));
            goto cleanup;
        }
    }

    if (!g_file_test (image_file, G_FILE_TEST_EXISTS)) {
        g_printerr (_("The image file '%s' does not exist\n"), image_file);
        goto cleanup;
    }

    if (!g_file_test (key_file, G_FILE_TEST_EXISTS)) {
        g_printerr (_("The key file '%s' does not exist\n"), key_file);
        goto cleanup;
    }

    retval = enable_pam_mount (argv[2], image_file, key_file);
    if (!retval)
        g_printerr (_("Failed to enable pam_mount\n"));
    else
        g_printerr (_("pam_mount is now enabled for %s\n"), argv[2]);

cleanup:
    g_free (image_file);
    g_free (key_file);
    return retval;
}

/*
 * Remove home directory entries from pam_mount.conf
 */
static gboolean command_disable_pam_mount (char *cmd, int argc, char *argv[])
{
    struct passwd *pent;
    GError *err = NULL;
    GOptionContext *ctx;
    gboolean ret, remove_all = FALSE;

    GOptionEntry entries[] = {
        { "all", 0, 0, G_OPTION_ARG_NONE, &remove_all, N_("Disable pam_mount for all users"), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    ctx = g_option_context_new ("user");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != (remove_all ? 2 : 3))
        show_command_help (ctx, cmd, argv);

    g_option_context_free (ctx);
    
    if (remove_all) {
        ret = disable_pam_mount (NULL);
    } else {
        pent = getpwnam (argv[2]);
        if (!pent) {
            g_printerr (_("Failed to lookup user %s\n"), argv[2]);
            return FALSE;
        }

        ret = disable_pam_mount (argv[2]);
    } 

    if (!ret) {
        g_printerr (_("Failed to disable pam_mount\n"));
    } else if (remove_all) {
        g_printerr (_("pam_mount is disabled for all users\n"));
    } else {
        g_printerr (_("pam_mount is disabled for %s\n"), argv[2]);
    }
    
    return ret;
}

/*
 * Create a new key that can be used with the --extra-key-file option
 * when creating a new image.  This is useful for admins.
 */
static gboolean command_create_key (char *cmd, int argc, char *argv[])
{
    gchar *key_data = NULL, *password = NULL;
    GOptionContext *ctx;
    GError *err = NULL;
    gboolean ret, retval = FALSE, no_verify = FALSE, force = FALSE;
    size_t key_size = KEY_DATA_SIZE;

    GOptionEntry entries[] = {
        { "no-verify", 0, 0, G_OPTION_ARG_NONE, &no_verify, N_("Don't verify the passphrase"), NULL },
        { "force", 0, 0, G_OPTION_ARG_NONE, &force, N_("Overwrite an existing key"), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    ctx = g_option_context_new ("new_key_file");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != 3)
        show_command_help (ctx, cmd, argv);

    g_option_context_free (ctx);

    if (!force && g_file_test (argv[2], G_FILE_TEST_EXISTS)) {
        g_printerr (_("The key file already exists.  Use --force to overwrite it.\n"));
        goto cleanup;
    }

    if (!get_random_key_data (&key_data, key_size)) {
        g_printerr (_("Failed to generate key data\n"));
        goto cleanup;
    }

    if (!get_passphrase (_("Enter a password for the new key"),
        !no_verify, &password)) {
        g_printerr (_("Failed to get password\n"));
        goto cleanup;
    }

    if (!encrypt_key (argv[2], password, key_data, key_size)) {
        g_printerr (_("Failed to create image key\n"));
        goto cleanup;
    }

    if (chmod (argv[2], 0600)) {
        g_printerr (_("Failed to set permissions for key file\n"));
        goto cleanup;
    }

    retval = TRUE;
    g_print (_("Done.\n"));

cleanup:
    if (password) {
        memset (password, 0, strlen (password));
        munlock (password, strlen (password));
    }

    if (key_data) {
        memset (key_data, 0, key_size);
        munlock (key_data, key_size);
    }

    g_free (password);
    g_free (key_data);
    return retval;
}

/*
 * Open a LUKS image
 */
static gboolean command_open_luks_image (char *cmd, int argc, char *argv[]) 
{
    GOptionContext *ctx;
    GError *err = NULL;
    gchar *key_file = NULL, *loop_device = NULL, *map_device = NULL, *mount_point = NULL, *fs_type = NULL;
    gboolean ret, retval = FALSE;

    GOptionEntry entries[] = {
        { "mount", 0, 0, G_OPTION_ARG_STRING, &mount_point, N_("Mount the image at the specified directory"), NULL },
        { "key-file", 0, 0, G_OPTION_ARG_STRING, &key_file, N_("The image key file"), NULL },
        { "fs-type", 0, 0, G_OPTION_ARG_STRING, &fs_type, N_("The filesystem type. The default is ext3"), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    ctx = g_option_context_new ("image");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != 3)
        show_command_help (ctx, cmd, argv);
   
    if (!g_file_test (argv[2], G_FILE_TEST_EXISTS)) {
        g_printerr (_("%s does not exist\n"), argv[2]);
        return FALSE;
    }

    /* make sure we're using a valid fs_type if --mount was given */
    if (mount_point && fs_type && !is_filesystem_supported (fs_type)) {
        gchar *fs = get_supported_filesystems (); 
        g_printerr (_("%s is not a supported file system\nSupported file "
                    "systems are: %s\n"), fs_type, fs);
        g_free (fs);
        return FALSE;
    }

    /* unlock the image */
    if (!unlock_image (argv[2], key_file, &map_device, &loop_device)) {
        g_printerr (_("Failed to open image\n"));
        goto cleanup;
    }
    
    /* mount the device if --mount was given */
    if (mount_point) {
        if (!g_file_test (mount_point, G_FILE_TEST_IS_DIR)) {
            g_printerr (_("%s is not a directory\n"), mount_point);
            goto cleanup;
        }

        if (!mount_dev (fs_type ? fs_type : "ext3", map_device, mount_point)) {
            g_printerr (_("Failed to mount device\n"));
            goto cleanup;
        }

        g_print (_("%s is now mounted at %s\n"), argv[2], mount_point);
    } else {
        g_print (_("%s is now available as device %s\n"), argv[2], map_device);
    }

    retval = TRUE;

cleanup:
    g_free (loop_device);
    g_free (map_device);
    return retval;
}

/*
 * Close a LUKS image
 */
static gboolean command_close_luks_image (char *cmd, int argc, char *argv[]) 
{
    GOptionContext *ctx;
    GError *err = NULL;
    gchar *loop_dev = NULL, *map_dev = NULL, *mount_point = NULL;
    gboolean ret, retval = FALSE;

    ctx = g_option_context_new ("image_file");
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc != 3)
        show_command_help (ctx, cmd, argv);

    if (!loop_find_devs_from_image (argv[2], &map_dev, &loop_dev)) {
        g_printerr (_("Unable to find device\n"));
        goto cleanup;
    }

    /* unmount if necessary */
    if (map_dev && get_mount_point (map_dev, &mount_point) && umount (mount_point)) {
        g_printerr (_("Failed to umount: %s\n"), strerror (errno));
        goto cleanup;
    }
   
    /* close the map device */
    if (map_dev && !luks_close (map_dev)) {
        g_printerr (_("Unable to close mapped device\n"));
        goto cleanup;
    }

    /* close the loop device */
    if (loop_dev && !loop_close (loop_dev)) {
        g_printerr (_("Unable to close loop device\n"));
        goto cleanup;
    }
    
    g_print (_("Done.\n"));
    retval = TRUE;

cleanup:
    g_free (loop_dev);
    g_free (map_dev);
    g_free (mount_point);
    return retval;
}

/*
 * Add/remove data from a user's public directory
 */
static gboolean command_public_data (char *cmd, int argc, char *argv[], gboolean add_data) 
{
    struct passwd *pent;
    GOptionContext *ctx;
    GError *err = NULL;
    gchar *map_device = NULL, *loop_device = NULL, *mount_point = NULL;
    gchar *pm_im = NULL, *pm_kf = NULL, *pm_fs = NULL;
    gchar *fs_type = NULL;
    gboolean ret, retval = FALSE;
    int i;
    
    GOptionEntry entries[] = {
        { "fs-type", 0, 0, G_OPTION_ARG_STRING, &fs_type, N_("The filesystem type. The default is ext3."), NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };

    ctx = g_option_context_new ("user path [path1 path2 ...]");
    g_option_context_add_main_entries (ctx, entries, NULL);
    ret = g_option_context_parse (ctx, &argc, &argv, &err);
    if (!ret) {
        g_printerr (_("parsing failed: %s\n"), err->message);
        g_error_free (err);
        g_option_context_free (ctx);
        return FALSE;
    }

    if (argc < 4)
        show_command_help (ctx, cmd, argv);
    
    pent = getpwnam (argv[2]);
    if (!pent) {
        g_printerr (_("Failed to lookup user '%s'\n"), argv[2]);
        return FALSE;
    }

    /* make sure we're using a valid fs_type */
    if (fs_type && !is_filesystem_supported (fs_type)) {
        gchar *fs = get_supported_filesystems (); 
        g_printerr (_("%s is not a supported file system\nSupported file "
                    "systems are: %s\n"), fs_type, fs);
        g_free (fs);
        return FALSE;
    }

    /*
     * Get the image, key file, and fs info from pam_mount.conf
     */
    if (!pam_mount_is_setup_for_user (argv[2], &pm_im, &pm_kf, &pm_fs)) {
        g_printerr (_("Pam mount is not setup for '%s'\n"), argv[2]);
        return FALSE;
    }

    if (loop_find_devs_from_image (pm_im, NULL, NULL)) {
        g_printerr (_("%s is currently in use.  Unable to continue.\n"), pm_im);
        goto cleanup;
    }

    if (!unlock_image (pm_im, pm_kf, &map_device, &loop_device)) {
        g_printerr (_("Failed to unlock image\n"));
        goto cleanup;
    }
    
    if (!temp_mount (fs_type ? fs_type : "ext3", map_device, &mount_point)) {
        g_printerr (_("Failed to mount image\n"));
        goto cleanup;
    }

    for (i = 3; i < argc; i++) {
        if (add_data) {
            if (!add_public_data (argv[2], pent->pw_dir, mount_point, argv[i])) {
                g_printerr (_("Failed to add %s\n"), argv[i]);
                goto cleanup;
            }
        } else {
            if (!remove_public_data (argv[2], pent->pw_dir, mount_point, argv[i])) {
                g_printerr (_("Failed to remove %s\n"), argv[i]);
                goto cleanup;
            }
        }
    }

    g_print (_("Done.\n"));
    retval = TRUE;

cleanup:
    if (mount_point)
        umount (mount_point);
    if (loop_device && g_file_test (map_device, G_FILE_TEST_EXISTS)) 
        luks_close (map_device);
    if (loop_device)
        loop_close (loop_device);
    
    g_free (loop_device);
    g_free (map_device);
    g_free (mount_point);
    g_free (pm_im);
    g_free (pm_kf);
    g_free (pm_fs);
    return retval;
}

static gboolean command_add_public_data (char *cmd, int argc, char *argv[])
{
    
    return command_public_data (cmd, argc, argv, TRUE);
}

static gboolean command_remove_public_data (char *cmd, int argc, char *argv[]) 
{
    return command_public_data (cmd, argc, argv, FALSE);
}

/*
 * Print individual command descriptions.
 */
static void print_command_description (gpointer key, gpointer value, gpointer user_data)
{
    Command *cmd = value;
    g_printerr ("%-15s %s\n", cmd->name, cmd->description);
}

/*
 * Print the usage message and exit.
 */
static void usage (const char *me)
{
    g_printerr (_("\nusage: %s [COMMAND] [COMMAND-OPTIONS] "
                "arg1 arg2...\n\nCOMMANDS\n"), g_path_get_basename (me));
    g_hash_table_foreach (commands, print_command_description, NULL);
    g_printerr (_("\nYou can run %s [COMMAND] --help for more "
                "information on a command.\n"), g_path_get_basename (me));
    exit(1);
}

/*
 * Add command meta data to our command set.
 */
static void register_command (gchar *name, const gchar *args, const gchar *description,
                              gboolean root, gboolean (*run_func) (char *cmd, int argc, char *argv[]))
{
    Command *cmd = g_malloc (sizeof (Command));
    cmd->name = g_strdup (name);
    cmd->arguments = g_strdup (args);
    cmd->description = g_strdup (description);
    cmd->requires_root = root;
    cmd->execute = run_func;
    g_hash_table_insert (commands, name, cmd);
}

/*
 * Free our Command structs.
 */
static void free_values (gpointer data) 
{
    Command *cmd = data;
    g_free (cmd->name);
    g_free (cmd->arguments);
    g_free (cmd->description);
    g_free (cmd);
}

/*
 * This is where the magic happens
 */
int main (int argc, char *argv[])
{
    Command *cmd;
    gboolean ret;

    bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
    
    commands = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, free_values);
    register_command ("make-ehd", "user size_in_mb",
                      _("Create an encrypted home directory image and image key"),
                      TRUE, command_make_encrypted_home);
    register_command ("enlarge-image", "image size_to_add_in_mb",
                      _("Enlarge a disk image and it's file system"),
                      TRUE, command_enlarge_image);
    register_command ("passwd", "key_file",
                      _("Change the password used to encrypt/decrypt a key file"),
                      FALSE, command_change_password);
    register_command ("pm-enable", "user",
                      _("Enable pam_mount with encrypted home directories"),
                      TRUE, command_enable_pam_mount);
    register_command ("pm-disable", "user",
                      _("Disable pam_mount with encrypted home directories"),
                      TRUE, command_disable_pam_mount);
    register_command ("create-image", "image size_in_mb",
                      _("Create an arbitrary LUKS image"),
                      TRUE, command_create_luks_image);
    register_command ("format", "device",
                      _("Create a LUKS partition on a device"),
                      TRUE, command_make_luks_device);
    register_command ("create-key", "new_key_file",
                      _("Create a new key that can be added to a LUKS image"),
                      TRUE, command_create_key);
    register_command ("open", "image",
                      _("Open a LUKS image"),
                      TRUE, command_open_luks_image);
    register_command ("close", "image",
                      _("Close devices using a LUKS image"),
                      TRUE, command_close_luks_image);
    register_command ("pd-add", "user image_file fs_type",
                      _("Add public data"),
                      TRUE, command_add_public_data);
    register_command ("pd-remove", "user image_file fs_type",
                      _("Remove public data"),
                      TRUE, command_remove_public_data);
    
    if (argc < 2 || !strncmp (argv[1], "--help", 6))
        usage (argv[0]);

    cmd = g_hash_table_lookup (commands, argv[1]);
    if (!cmd)
        usage (argv[0]);

    if (cmd->requires_root && geteuid () != 0) {
        g_printerr (_("You must be root to run this command\n"));
        return 1;
    }

    umask (077);
    ret = cmd->execute (argv[1], argc, argv);
    g_hash_table_destroy (commands);
    
    return ret ? 0 : 1;
}
