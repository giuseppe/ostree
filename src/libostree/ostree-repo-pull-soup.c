/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2011,2012,2013 Colin Walters <walters@verbum.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Colin Walters <walters@verbum.org>
 */

#include "config.h"

#include "libglnx.h"
#include "ostree.h"
#include "otutil.h"

#ifdef HAVE_LIBSOUP

#include "ostree-core-private.h"
#include "ostree-repo-private.h"
#include "ostree-repo-static-delta-private.h"
#include "ostree-metalink.h"
#include "ot-fs-utils.h"

#include <gio/gunixinputstream.h>

#define OSTREE_REPO_PULL_CONTENT_PRIORITY  (OSTREE_FETCHER_DEFAULT_PRIORITY)
#define OSTREE_REPO_PULL_METADATA_PRIORITY (OSTREE_REPO_PULL_CONTENT_PRIORITY - 100)

typedef struct {
  OstreeRepo   *repo;
  OstreeRepoPullFlags flags;
  char         *remote_name;

  OstreeFetcher *fetcher;
  SoupURI          *base_uri;
  GMainContext    *main_context;
  GCancellable *cancellable;

  GBytes           *summary_data;
} OtPullData;

typedef struct {
  OstreeFetchService *object;
  GDBusMethodInvocation *invocation;
} FetchDBusData;

static SoupURI *
suburi_new (SoupURI   *base,
            const char *first,
            ...) G_GNUC_NULL_TERMINATED;

static SoupURI *
suburi_new (SoupURI   *base,
            const char *first,
            ...)
{
  va_list args;
  GPtrArray *arg_array;
  const char *arg;
  char *subpath;
  SoupURI *ret;

  arg_array = g_ptr_array_new ();
  g_ptr_array_add (arg_array, (char*)soup_uri_get_path (base));
  g_ptr_array_add (arg_array, (char*)first);

  va_start (args, first);

  while ((arg = va_arg (args, const char *)) != NULL)
    g_ptr_array_add (arg_array, (char*)arg);
  g_ptr_array_add (arg_array, NULL);

  subpath = g_build_filenamev ((char**)arg_array->pdata);
  g_ptr_array_unref (arg_array);

  ret = soup_uri_copy (base);
  soup_uri_set_path (ret, subpath);
  g_free (subpath);

  va_end (args);

  return ret;
}

gboolean handle_progress (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation)
{
  guint64 bytes_transferred = _ostree_fetcher_bytes_transferred (pull_data->fetcher);
  ostree_async_progress_set_uint64 (pull_data->progress, "bytes-transferred", bytes_transferred);
}

static void
fetch_file_on_complete (GObject        *object,
                        GAsyncResult   *result,
                        gpointer        user_data)
{
  OstreeFetcher *fetcher = (OstreeFetcher *)object;
  GError *local_error = NULL;
  GDBusMethodInvocation *invocation = user_data;
  g_autofree char *temp_path =  _ostree_fetcher_request_uri_with_partial_finish (fetcher, result, &local_error);
  if (local_error)
    g_dbus_method_invocation_return_gerror (invocation, local_error);
  else
    g_dbus_method_invocation_return_value (invocation, g_variant_new ("(s)", temp_path));
}

static void
fetch_bytes_on_complete (GObject        *object,
                         GAsyncResult   *result,
                         gpointer        user_data)
{
  OstreeFetcher *fetcher = (OstreeFetcher *)object;
  GError *local_error = NULL;
  GError **error = &local_error;
  GDBusMethodInvocation *invocation = user_data;
  GBytes* bytes_data = NULL;

  if (!_ostree_fetcher_stream_uri_finish (fetcher, result, FALSE, TRUE, &bytes_data, pull_data->cancellable, error))
    g_dbus_method_invocation_return_gerror (invocation, local_error);
  else
    g_dbus_method_invocation_return_value (invocation, ot_gvariant_new_ay_bytes (bytes_data));
}


static void
ref_fetch_on_complete (GObject        *object,
                       GAsyncResult   *result,
                       gpointer        user_data)
{
  OstreeFetcher *fetcher = (OstreeFetcher *)object;
  GError *local_error = NULL;
  GError **error = &local_error;
  GDBusMethodInvocation *invocation = user_data;
  GBytes* buf = NULL;

  if (!_ostree_fetcher_stream_uri_finish (fetcher, result, TRUE, FALSE, &buf, pull_data->cancellable, error))
    {
      g_dbus_method_invocation_return_gerror (invocation, local_error);
    }
  else
    {
      gsize len;
      g_autofree char* rev = g_bytes_unref_to_data (buf, &len);
      g_dbus_method_invocation_return_value (invocation, g_variant_new ("(s)", rev));
    }
}

static void
config_fetch_on_complete (GObject        *object,
                          GAsyncResult   *result,
                          gpointer        user_data)
{
  OstreeFetcher *fetcher = (OstreeFetcher *)object;
  GError *local_error = NULL;
  GError **error = &local_error;
  GDBusMethodInvocation *invocation = user_data;
  GBytes* bytes = NULL;

  g_autofree char *contents = NULL;
  gsize len;
  g_autoptr(GKeyFile) remote_config = g_key_file_new ();
  g_autofree char *remote_mode_str = NULL;
  guint remote_mode;
  gboolean has_tombstone_comits;

  if (!_ostree_fetcher_stream_uri_finish (fetcher, result, TRUE, FALSE, &bytes, pull_data->cancellable, error))
    goto out;

  contents = g_bytes_unref_to_data (bytes, &len);

  if (!g_key_file_load_from_data (remote_config, contents, len, 0, error))
    goto out;

  if (!ot_keyfile_get_value_with_default (remote_config, "core", "mode", "bare",
                                          &remote_mode_str, error))
    goto out;

  if (!ostree_repo_mode_from_string (remote_mode_str, &remote_mode, error))
    goto out;

  if (!ot_keyfile_get_boolean_with_default (remote_config, "core", "tombstone-commits", FALSE,
                                            &has_tombstone_commits, error))
    goto out;

 out:
  if (local_error)
    g_dbus_method_invocation_return_gerror (invocation, local_error);
  else
    g_dbus_method_invocation_return_value (invocation,
      g_variant_new ("(ub)", remote_mode, has_tombstone_comits));
}

gboolean handle_fetch_config (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation)
{
  SoupURI *uri = suburi_new (pull_data->base_uri, "config", NULL);
  _ostree_fetcher_stream_uri_async (pull_data->fetcher,
                                    uri,
                                    OSTREE_MAX_METADATA_SIZE,
                                    OSTREE_REPO_PULL_METADATA_PRIORITY,
                                    cancellable,
                                    config_fetch_on_complete,
                                    pull_data);
  soup_uri_free (uri);
  return TRUE;
}

gboolean handle_fetch_delta_part (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation,
  const gchar *arg_from_revision,
  const gchar *arg_to_revision,
  const gchar *arg_branch,
  gint arg_index)
{
  g_autofree char *deltapart_path = _ostree_get_relative_static_delta_part_path (from_revision, to_revision, i);
  SoupURI *target_uri = suburi_new (pull_data->base_uri, deltapart_path, NULL);
  _ostree_fetcher_request_uri_with_partial_async (pull_data->fetcher, target_uri, size,
                                                  OSTREE_FETCHER_DEFAULT_PRIORITY,
                                                  pull_data->cancellable,
                                                  fetch_file_on_complete,
                                                  invocation);
  soup_uri_free (target_uri);
  return TRUE;
}

gboolean handle_fetch_delta_super (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation,
  const gchar *arg_from_revision,
  const gchar *arg_to_revision,
  const gchar *arg_branch)
{
  OtPullData *pull_data = fetch_data->pull_data;
  g_autofree char *delta_name = _ostree_get_relative_static_delta_superblock_path (from_revision, to_revision);
  SoupURI *target_uri = suburi_new (pull_data->base_uri, delta_name, NULL);
  _ostree_fetcher_stream_uri_async (pull_data->fetcher,
                                    target_uri,
                                    OSTREE_MAX_METADATA_SIZE,
                                    OSTREE_REPO_PULL_METADATA_PRIORITY,
                                    cancellable,
                                    fetch_file_on_complete,
                                    fetch_data);
  soup_uri_free (target_uri);
  return TRUE;
}

gboolean handle_fetch_object (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation,
  guint arg_objtype,
  const gchar *arg_checksum)
{
  gboolean is_meta = OSTREE_OBJECT_TYPE_IS_META (objtype);
  OstreeObjectType objtype = arg_objtype;
  g_autofree char *objpath = NULL;
  SoupURI *obj_uri = NULL;

  g_debug ("queuing fetch of %s.%s", checksum, ostree_object_type_to_string (objtype));

  objpath = _ostree_get_relative_object_path (checksum, objtype, TRUE);
  obj_uri = suburi_new (pull_data->base_uri, objpath, NULL);

  _ostree_fetcher_request_uri_with_partial_async (pull_data->fetcher, obj_uri,
                                                  expected_max_size,
                                                  is_meta ? OSTREE_REPO_PULL_METADATA_PRIORITY
                                                          : OSTREE_REPO_PULL_CONTENT_PRIORITY,
                                                  pull_data->cancellable,
                                                  fetch_file_on_complete, invocation);
  soup_uri_free (obj_uri);
  return TRUE;
}

gboolean handle_fetch_ref (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation,
  const gchar *arg_name)
{
  SoupURI *target_uri = suburi_new (pull_data->base_uri, "refs", "heads", ref, NULL);
  _ostree_fetcher_stream_uri_async (pull_data->fetcher,
                                    target_uri,
                                    OSTREE_MAX_METADATA_SIZE,
                                    OSTREE_REPO_PULL_METADATA_PRIORITY,
                                    cancellable,
                                    revision_fetch_on_complete,
                                    fetch_data);
  soup_uri_free (target_uri);
  return TRUE;
}

gboolean handle_fetch_summary (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation)
{
  SoupURI *uri = suburi_new (pull_data->base_uri, "summary", NULL);
  pull_data->n_outstanding[FETCH_SUMMARY]++;
  _ostree_fetcher_stream_uri_async (pull_data->fetcher,
                                    uri,
                                    OSTREE_MAX_METADATA_SIZE,
                                    OSTREE_REPO_PULL_METADATA_PRIORITY,
                                    cancellable,
                                    summary_fetch_on_complete,
                                    pull_data);
  soup_uri_free (uri);
  return TRUE;
}

gboolean handle_fetch_summary_sig (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation)
{
  SoupURI *uri = suburi_new (pull_data->base_uri, "summary.sig", NULL);
  pull_data->n_outstanding[FETCH_SUMMARY_SIG]++;
  _ostree_fetcher_stream_uri_async (pull_data->fetcher,
                                    uri,
                                    OSTREE_MAX_METADATA_SIZE,
                                    OSTREE_REPO_PULL_METADATA_PRIORITY,
                                    cancellable,
                                    summary_sig_fetch_on_complete,
                                    pull_data);
  soup_uri_free (uri);
  return TRUE;
}

static void
metalink_fetch_on_complete (GObject        *object,
                            GAsyncResult   *result,
                            gpointer        user_data)
{
  GError *local_error = NULL;
  GError **error = &local_error;
  GDBusMethodInvocation *invocation = user_data;

  FetchMetalinkResult* out = _ostree_metalink_request_finish (object, result, error);

  {
    g_autofree char *repo_base = g_path_get_dirname (soup_uri_get_path (out->target_uri));
    pull_data->base_uri = soup_uri_copy (out->target_uri);
    soup_uri_set_path (pull_data->base_uri, repo_base);
  }

  pull_data->summary_data = out->data;

  if (local_error != NULL)
      goto out;
}

gboolean handle_open_metalink (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation,
  const gchar *arg_metalink_uri)
{
  SoupURI *metalink_uri = soup_uri_new (metalink_url_str);
  if (!metalink_uri)
    {
      g_dbus_method_invocation_return_error (invocation, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Invalid metalink URL: %s", metalink_url_str);
      return TRUE;
    }
  else
    {
      _ostree_metalink_request_async (pull_data->fetcher,
                                      metalink_uri,
                                      "summary",
                                      OSTREE_MAX_METADATA_SIZE,
                                      OSTREE_REPO_PULL_METADATA_PRIORITY,
                                      metalink_fetch_on_complete,
                                      pull_data,
                                      cancellable);
      soup_uri_free (metalink_uri);
    }
  return TRUE;
}

gboolean handle_open_url (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation,
  const gchar *baseurl)
{
  pull_data->base_uri = soup_uri_new (baseurl);

  if (!pull_data->base_uri)
    {
      g_dbus_method_invocation_return_error (invocation, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "Failed to parse url '%s'", baseurl);
    }
  else
    {
      ostree_fetch_service_complete_open_url (object, invocation);
    }
}

gboolean handle_new (
  OstreeFetchService *object,
  GDBusMethodInvocation *invocation,
  gboolean arg_tls_permissive,
  const gchar *arg_tls_client_cert_path,
  const gchar *arg_tls_client_key_path,
  const gchar *arg_tls_ca_path,
  const gchar *arg_http_proxy)
{
  OstreeFetcher *fetcher = NULL;
  OstreeFetcherConfigFlags fetcher_flags = 0;
  gboolean success = FALSE;

  g_return_val_if_fail (OSTREE_IS_REPO (self), FALSE);

  if (tls_permissive)
    fetcher_flags |= OSTREE_FETCHER_FLAGS_TLS_PERMISSIVE;

  fetcher = _ostree_fetcher_new (self->tmp_dir_fd, fetcher_flags);

  if (tls_client_cert_path != NULL)
    {
      g_autoptr(GTlsCertificate) client_cert = NULL;

      g_assert (tls_client_key_path != NULL);

      client_cert = g_tls_certificate_new_from_files (tls_client_cert_path,
                                                      tls_client_key_path,
                                                      error);
      if (client_cert == NULL)
        goto out;

      _ostree_fetcher_set_client_cert (fetcher, client_cert);
    }

  if (tls_ca_path != NULL)
    {
      g_autoptr(GTlsDatabase) db = NULL;

      db = g_tls_file_database_new (tls_ca_path, error);
      if (db == NULL)
        goto out;

      _ostree_fetcher_set_tls_database (fetcher, db);
    }

  if (http_proxy != NULL)
    _ostree_fetcher_set_proxy (fetcher, http_proxy);

  success = TRUE;

out:
  if (!success)
    g_clear_object (&fetcher);

  return TRUE;
}

int
main (int argc, char **argv)
{
  GError *local_error = NULL;
  GError **error = &local_error;
  int ret;
  OstreeFetchService *interface = ostree_fetch_service_skeleton_new ();

  static int socket_fd = -1;
  glnx_unref_object GSocket *socket = NULL;
  glnx_unref_object GSocketConnection *stream = NULL;
  g_autofree char* guid = g_dbus_generate_guid ();
  glnx_unref_object GDBusConnection* connection = NULL;

  GOptionContext  *context = NULL;
  static GOptionEntry entries []   = {
    { "socketfd", 0, 0, G_OPTION_ARG_INT, &socket_fd, "D-Bus Socket File Descriptor", "FD" },
    { NULL }
  };

  setlocale (LC_ALL, "");
  g_set_prgname (argv[0]);

  context = g_option_context_new (_("OSTree Libsoup-based Fetcher"));
  g_option_context_add_main_entries (context, entries, NULL);
  g_option_context_parse (context, &argc, &argv, NULL);
  g_option_context_free (context);

  /* Set up interface */
  g_signal_connect (interface,
                    "handle-hello-world",
                    G_CALLBACK (on_handle_hello_world),
                    some_user_data);

  /* Build up the server connection */
  socket = g_socket_new_from_fd (pair[1], &error);
  g_assert_no_error (error);

  stream = g_socket_connection_factory_create_connection (socket);
  g_assert (stream != NULL);

  connection = g_dbus_connection_new_sync (
                              G_IO_STREAM (stream), guid,
                              G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_SERVER |
                              G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_ALLOW_ANONYMOUS,
                              NULL, NULL, error);

  if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (interface),
                                         connection,
                                         "/ostree/fetch",
                                         error))
    goto out;

  loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (loop);
  g_main_loop_unref (loop);

  if (error != NULL)
    {
      int is_tty = isatty (1);
      const char *prefix = "";
      const char *suffix = "";
      if (is_tty)
        {
          prefix = "\x1b[31m\x1b[1m"; /* red, bold */
          suffix = "\x1b[22m\x1b[0m"; /* bold off, color reset */
        }
      g_printerr ("%serror: %s%s\n", prefix, suffix, error->message);
      g_error_free (error);
    }

  return ret;
}
