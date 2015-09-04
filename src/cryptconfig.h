#ifndef CRYPTCONFIG_H
#define CRYPTCONFIG_H

#include <config.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gi18n-lib.h>

/*
 * This is limited by a buffer in pam_mount
 */
#define KEY_DATA_SIZE 256
#define BUFF_SIZE 256
#define KEY_FILE_SIZE_THRESHOLD 1048576
#define PAM_SERVICES_DIR SYSCONFDIR "/pam.d"
#define PAM_MOUNT_CONF SYSCONFDIR "/security/pam_mount.conf.xml"
#define CRYPTCONFIG_CONF SYSCONFDIR "/cryptconfig.conf"

gboolean luks_close (char *map_name);
gboolean luks_format (const char *pass, size_t pass_size, char *device);
gboolean luks_open (const char *pass, size_t pass_size,
                    char *device, char *map_name);
gboolean luks_add_key (char *device, char *existing_key, size_t ek_size,
                       char *new_key, size_t nk_size);
gboolean add_key_file_to_device (char *device, char *extra_key_file,
                                 char *curr_key, long curr_key_len);

gboolean decrypt_key (const char *key_file, const char *pass,
                      char **key_data, int *key_data_size);
gboolean encrypt_key (const char *key_file, const char *pass_new,
                      const char *key_data, int key_size);

gboolean loop_open (const char *image, char **device);
gboolean loop_close (const char *loop_device);
gboolean loop_find_devs_from_image (const char *image,
                                    gchar **map_dev, gchar **loop_dev);

gboolean create_image_zero (const char *image, guint64 size_in_mb);
gboolean create_image_random (const char *image, guint64 size_in_mb);

gchar *get_supported_filesystems (void);
gboolean is_mounted (const char *dev);
gboolean get_mount_point (const char *dev, char **mp);
gboolean is_filesystem_supported (const char *fs_type);
gboolean create_filesystem (char *device, char *fs_type);
gboolean resize_filesystem (char *device);
gboolean check_min_fs_size (const char *fs_type, gint64 image_size, gint64 *req_size);

gboolean pam_mount_is_setup_for_user (const char * user, char **image, char **key, char **fs_type);
gboolean enable_pam_mount (const char *user, const char *image_file, const char *key_file); 
gboolean disable_pam_mount (const char *user);

gchar *path_to_map_name (const char *path);
gboolean unlock_image (const char *image_file, const char *key_file, char **map_device, char **loop_dev);
gboolean check_disk_space (char *image, char *current_home, guint64 *home_size);
gboolean check_requested_space (const char *path, guint64 req_size);
gboolean copy_user_data (const char *src, const char *dest);
gboolean get_passphrase (const char *prompt, int verify, gchar **passphrase); 
gboolean enlarge_image (const char *image, guint64 size_to_add_in_mb);
gboolean get_random_key_data (gchar **key_data, size_t key_size);
gboolean temp_mount (char *fs_type, char *device, char **mount_point);
gboolean mount_dev (char *fs_type, char *device, char *mount_point);
gboolean remove_home_directory (struct passwd *pent);
gboolean parse_size (const char *arg, gint64 *size_in_mb);

gboolean add_public_data (const char *user, const char *normal_hd,
                          const char *enc_hd, const char *path);
gboolean remove_public_data (const char *user, const char *normal_hd,
                             const char *enc_hd, const char *path);

#endif
