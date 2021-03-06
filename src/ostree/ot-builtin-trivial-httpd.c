/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2011,2013 Colin Walters <walters@verbum.org>
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
 */

#include "config.h"

#include <libsoup/soup.h>

#include "ot-main.h"
#include "ot-builtins.h"
#include "ostree.h"
#include "otutil.h"

#include <sys/socket.h>
#include <sys/prctl.h>
#include <signal.h>

static char *opt_port_file = NULL;
static gboolean opt_daemonize;
static gboolean opt_autoexit;
static gboolean opt_force_ranges;

typedef struct {
  GFile *root;
  gboolean running;
} OtTrivialHttpd;

static GOptionEntry options[] = {
  { "daemonize", 'd', 0, G_OPTION_ARG_NONE, &opt_daemonize, "Fork into background when ready", NULL },
  { "autoexit", 0, 0, G_OPTION_ARG_NONE, &opt_autoexit, "Automatically exit when directory is deleted", NULL },
  { "port-file", 'p', 0, G_OPTION_ARG_FILENAME, &opt_port_file, "Write port number to PATH (- for standard output)", "PATH" },
  { "force-range-requests", 0, 0, G_OPTION_ARG_NONE, &opt_force_ranges, "Force range requests by only serving half of files", NULL },
  { NULL }
};

static int
compare_strings (gconstpointer a, gconstpointer b)
{
  const char **sa = (const char **)a;
  const char **sb = (const char **)b;

  return strcmp (*sa, *sb);
}

static GString *
get_directory_listing (const char *path)
{
  GPtrArray *entries;
  GString *listing;
  char *escaped;
  DIR *dir;
  struct dirent *dent;
  int i;

  entries = g_ptr_array_new ();
  dir = opendir (path);
  if (dir)
    {
      while ((dent = readdir (dir)))
        {
          if (!strcmp (dent->d_name, ".") ||
              (!strcmp (dent->d_name, "..") &&
               !strcmp (path, "./")))
            continue;
          escaped = g_markup_escape_text (dent->d_name, -1);
          g_ptr_array_add (entries, escaped);
        }
      closedir (dir);
    }

  g_ptr_array_sort (entries, (GCompareFunc)compare_strings);

  listing = g_string_new ("<html>\r\n");
  escaped = g_markup_escape_text (strchr (path, '/'), -1);
  g_string_append_printf (listing, "<head><title>Index of %s</title></head>\r\n", escaped);
  g_string_append_printf (listing, "<body><h1>Index of %s</h1>\r\n<p>\r\n", escaped);
  g_free (escaped);
  for (i = 0; i < entries->len; i++)
    {
      g_string_append_printf (listing, "<a href=\"%s\">%s</a><br>\r\n",
                              (char *)entries->pdata[i], 
                              (char *)entries->pdata[i]);
      g_free (entries->pdata[i]);
    }
  g_string_append (listing, "</body>\r\n</html>\r\n");

  g_ptr_array_free (entries, TRUE);
  return listing;
}

/* Only allow reading files that have o+r, and for directories, o+x.
 * This makes this server relatively safe to use on multiuser
 * machines.
 */
static gboolean
is_safe_to_access (struct stat *stbuf)
{
  /* Only regular files or directores */
  if (!(S_ISREG (stbuf->st_mode) || S_ISDIR (stbuf->st_mode)))
    return FALSE;
  /* Must be o+r */
  if (!(stbuf->st_mode & S_IROTH))
    return FALSE;
  /* For directories, must be o+x */
  if (S_ISDIR (stbuf->st_mode) && !(stbuf->st_mode & S_IXOTH))
    return FALSE;
  return TRUE;
}

static void
close_socket (SoupMessage *msg, gpointer user_data)
{
	SoupSocket *sock = user_data;
	int sockfd;

	/* Actually calling soup_socket_disconnect() here would cause
	 * us to leak memory, so just shutdown the socket instead.
	 */
	sockfd = soup_socket_get_fd (sock);
#ifdef G_OS_WIN32
	shutdown (sockfd, SD_SEND);
#else
	shutdown (sockfd, SHUT_WR);
#endif
}

static void
do_get (OtTrivialHttpd    *self,
        SoupServer        *server,
        SoupMessage       *msg,
        const char        *path,
        SoupClientContext *context)
{
  char *slash;
  int ret;
  struct stat stbuf;
  gs_free char *safepath = NULL;

  if (strstr (path, "../") != NULL)
    {
      soup_message_set_status (msg, SOUP_STATUS_FORBIDDEN);
      goto out;
    }

  if (path[0] == '/')
    path++;

  safepath = g_build_filename (gs_file_get_path_cached (self->root), path, NULL);

  do
    ret = stat (safepath, &stbuf);
  while (ret == -1 && errno == EINTR);
  if (ret == -1)
    {
      if (errno == EPERM)
        soup_message_set_status (msg, SOUP_STATUS_FORBIDDEN);
      else if (errno == ENOENT)
        soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
      else
        soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
      goto out;
    }

  if (!is_safe_to_access (&stbuf))
    {
      soup_message_set_status (msg, SOUP_STATUS_FORBIDDEN);
      goto out;
    }

  if (S_ISDIR (stbuf.st_mode))
    {
      slash = strrchr (safepath, '/');
      if (!slash || slash[1])
        {
          gs_free char *redir_uri = NULL;

          redir_uri = g_strdup_printf ("%s/", soup_message_get_uri (msg)->path);
          soup_message_set_redirect (msg, SOUP_STATUS_MOVED_PERMANENTLY,
                                     redir_uri);
        }
      else
        {
          gs_free char *index_realpath = g_strconcat (safepath, "/index.html", NULL);
          if (stat (index_realpath, &stbuf) != -1)
            {
              gs_free char *index_path = g_strconcat (path, "/index.html", NULL);
              do_get (self, server, msg, index_path, context);
            }
          else
            {
              GString *listing = get_directory_listing (safepath);
              soup_message_set_response (msg, "text/html",
                                         SOUP_MEMORY_TAKE,
                                         listing->str, listing->len);
              soup_message_set_status (msg, SOUP_STATUS_OK);
              g_string_free (listing, FALSE);
            }
        }
    }
  else 
    {
      if (!S_ISREG (stbuf.st_mode))
        {
          soup_message_set_status (msg, SOUP_STATUS_FORBIDDEN);
          goto out;
        }
      
      if (msg->method == SOUP_METHOD_GET)
        {
          GMappedFile *mapping;
          SoupBuffer *buffer;
          gsize buffer_length, file_size;
          SoupRange *ranges;
          int ranges_length;
          gboolean have_ranges;

          mapping = g_mapped_file_new (safepath, FALSE, NULL);
          if (!mapping)
            {
              soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
              goto out;
            }

          file_size = g_mapped_file_get_length (mapping);
          have_ranges = soup_message_headers_get_ranges(msg->request_headers, file_size, &ranges, &ranges_length);
          if (opt_force_ranges && !have_ranges && g_strrstr (path, "/objects") != NULL)
            {
              SoupSocket *sock;
              buffer_length = file_size/2;
              soup_message_headers_set_content_length (msg->response_headers, file_size);
              soup_message_headers_append (msg->response_headers,
                                           "Connection", "close");

              /* soup-message-io will wait for us to add
               * another chunk after the first, to fill out
               * the declared Content-Length. Instead, we
               * forcibly close the socket at that point.
               */
              sock = soup_client_context_get_socket (context);
              g_signal_connect (msg, "wrote-chunk", G_CALLBACK (close_socket), sock);
            }
          else
            buffer_length = file_size;

          if (have_ranges)
            {
              if (ranges_length > 0 && ranges[0].start >= file_size)
                {
                  soup_message_set_status (msg, SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE);
                  soup_message_headers_free_ranges (msg->request_headers, ranges);
                  goto out;
                }
              soup_message_headers_free_ranges (msg->request_headers, ranges);
            }
          buffer = soup_buffer_new_with_owner (g_mapped_file_get_contents (mapping),
                                               buffer_length,
                                               mapping, (GDestroyNotify)g_mapped_file_unref);
          soup_message_body_append_buffer (msg->response_body, buffer);
          soup_buffer_free (buffer);
        }
      else /* msg->method == SOUP_METHOD_HEAD */
        {
          gs_free char *length = NULL;

          /* We could just use the same code for both GET and
           * HEAD (soup-message-server-io.c will fix things up).
           * But we'll optimize and avoid the extra I/O.
           */
          length = g_strdup_printf ("%lu", (gulong)stbuf.st_size);
          soup_message_headers_append (msg->response_headers,
                                       "Content-Length", length);
        }
      soup_message_set_status (msg, SOUP_STATUS_OK);
    }
 out:
  return;
}

static void
httpd_callback (SoupServer *server, SoupMessage *msg,
                const char *path, GHashTable *query,
                SoupClientContext *context, gpointer data)
{
  OtTrivialHttpd *self = data;
  SoupMessageHeadersIter iter;

  soup_message_headers_iter_init (&iter, msg->request_headers);

  if (msg->method == SOUP_METHOD_GET || msg->method == SOUP_METHOD_HEAD)
    do_get (self, server, msg, path, context);
  else
    soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
}

static void
on_dir_changed (GFileMonitor  *mon,
		GFile *file,
		GFile *other,
		GFileMonitorEvent  event,
		gpointer user_data)
{
  OtTrivialHttpd *self = user_data;

  if (event == G_FILE_MONITOR_EVENT_DELETED)
    {
      self->running = FALSE;
      g_main_context_wakeup (NULL);
    }
}

gboolean
ostree_builtin_trivial_httpd (int argc, char **argv, GCancellable *cancellable, GError **error)
{
  gboolean ret = FALSE;
  GOptionContext *context;
  const char *dirpath;
  OtTrivialHttpd appstruct = { 0, };
  OtTrivialHttpd *app = &appstruct;
  gs_unref_object SoupServer *server = NULL;
  gs_unref_object GFileMonitor *dirmon = NULL;

  context = g_option_context_new ("[DIR] - Simple webserver");

  if (!ostree_option_context_parse (context, options, &argc, &argv, OSTREE_BUILTIN_FLAG_NO_REPO, NULL, cancellable, error))
    goto out;

  if (argc > 1)
    dirpath = argv[1];
  else
    dirpath = ".";

  app->root = g_file_new_for_path (dirpath);

#if SOUP_CHECK_VERSION(2, 48, 0)
  server = soup_server_new (SOUP_SERVER_SERVER_HEADER, "ostree-httpd ", NULL);
  if (!soup_server_listen_all (server, 0, 0, error))
    goto out;
#else
  server = soup_server_new (SOUP_SERVER_PORT, 0,
                            SOUP_SERVER_SERVER_HEADER, "ostree-httpd ",
                            NULL);
#endif

  soup_server_add_handler (server, NULL, httpd_callback, app, NULL);
  if (opt_port_file)
    {
      gs_free char *portstr = NULL;
#if SOUP_CHECK_VERSION(2, 48, 0)
      GSList *listeners = soup_server_get_listeners (server);
      gs_unref_object GSocket *listener = NULL;
      gs_unref_object GSocketAddress *addr = NULL;
      
      g_assert (listeners);
      listener = g_object_ref (listeners->data);
      g_slist_free (listeners);
      listeners = NULL;
      addr = g_socket_get_local_address (listener, error);
      if (!addr)
        goto out;

      g_assert (G_IS_INET_SOCKET_ADDRESS (addr));
      
      portstr = g_strdup_printf ("%u\n", g_inet_socket_address_get_port ((GInetSocketAddress*)addr));
#else
      portstr = g_strdup_printf ("%u\n", soup_server_get_port (server));
#endif

      if (g_strcmp0 ("-", opt_port_file) == 0)
        {
          fputs (portstr, stdout); // not g_print - this must go to stdout, not a handler
          fflush (stdout);
        }
      else if (!g_file_set_contents (opt_port_file, portstr, strlen (portstr), error))
        goto out;
    }
#if !SOUP_CHECK_VERSION(2, 48, 0)
  soup_server_run_async (server);
#endif
  
  if (opt_daemonize)
    {
      pid_t pid = fork();
      if (pid == -1)
        {
          int errsv = errno;
          g_set_error_literal (error, G_IO_ERROR, g_io_error_from_errno (errsv),
                               g_strerror (errsv));
          goto out;
        }
      else if (pid > 0)
        {
          /* Parent */
          _exit (0);
        }
      /* Child, continue */
      /* Daemonising: close stdout/stderr so $() et al work on us */
      fclose (stdout);
      fclose (stdin);
    }
  else
    {
      /* Since we're used for testing purposes, let's just do this by
       * default.  This ensures we exit when our parent does.
       */
      if (prctl (PR_SET_PDEATHSIG, SIGTERM) != 0)
        {
          int errsv = errno;
          if (errsv != ENOSYS)
            {
              gs_set_error_from_errno (error, errsv);
              goto out;
            }
        }
    }

  app->running = TRUE;
  if (opt_autoexit)
    {
      gboolean is_symlink = FALSE;
      gs_unref_object GFileInfo *info = NULL;

      info = g_file_query_info (app->root,
                               G_FILE_ATTRIBUTE_STANDARD_IS_SYMLINK,
                               G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
                               cancellable, error);
      if (!info)
        goto out;

      is_symlink = g_file_info_get_is_symlink (info);

      if (is_symlink)
        dirmon = g_file_monitor_file (app->root, 0, cancellable, error);
      else
        dirmon = g_file_monitor_directory (app->root, 0, cancellable, error);

      if (!dirmon)
        goto out;
      g_signal_connect (dirmon, "changed", G_CALLBACK (on_dir_changed), app);
    }

  while (app->running)
    g_main_context_iteration (NULL, TRUE);
 
  ret = TRUE;
 out:
  g_clear_object (&app->root);
  if (context)
    g_option_context_free (context);
  return ret;
}
