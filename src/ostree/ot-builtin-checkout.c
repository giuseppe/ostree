/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2011 Colin Walters <walters@verbum.org>
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

#include "ot-builtins.h"
#include "ostree.h"

#include <gio/gunixinputstream.h>

#include <glib/gi18n.h>

static gboolean opt_user_mode;
static gboolean opt_no_triggers;
static char *opt_subpath;
static gboolean opt_union;
static gboolean opt_from_stdin;
static char *opt_from_file;

static GOptionEntry options[] = {
  { "user-mode", 'U', 0, G_OPTION_ARG_NONE, &opt_user_mode, "Do not change file ownership or initialize extended attributes", NULL },
  { "subpath", 0, 0, G_OPTION_ARG_STRING, &opt_subpath, "Checkout sub-directory PATH", "PATH" },
  { "union", 0, 0, G_OPTION_ARG_NONE, &opt_union, "Keep existing directories, overwrite existing files", NULL },
  { "no-triggers", 0, 0, G_OPTION_ARG_NONE, &opt_no_triggers, "Don't run triggers", NULL },
  { "from-stdin", 0, 0, G_OPTION_ARG_NONE, &opt_from_stdin, "Process many checkouts from standard input", NULL },
  { "from-file", 0, 0, G_OPTION_ARG_STRING, &opt_from_file, "Process many checkouts from input file", NULL },
  { NULL }
};

typedef struct {
  gboolean caught_error;
  GError **error;

  GMainLoop *loop;
} ProcessOneCheckoutData;

static void
on_checkout_complete (GObject         *object,
                      GAsyncResult    *result,
                      gpointer         user_data)
{
  ProcessOneCheckoutData *data = user_data;
  GError *local_error = NULL;

  if (!ostree_repo_checkout_tree_finish ((OstreeRepo*)object, result,
                                         &local_error))
    goto out;

 out:
  if (local_error)
    {
      if (!data->caught_error)
        {
          data->caught_error = TRUE;
          g_propagate_error (data->error, local_error);
        }
      else
        g_clear_error (&local_error);
    }
  g_main_loop_quit (data->loop);
}

static gboolean
process_one_checkout (OstreeRepo           *repo,
                      const char           *resolved_commit,
                      const char           *subpath,
                      GFile                *target,
                      GCancellable         *cancellable,
                      GError              **error)
{
  gboolean ret = FALSE;
  ProcessOneCheckoutData data;
  ot_lobj OstreeRepoFile *root = NULL;
  ot_lobj OstreeRepoFile *subtree = NULL;
  ot_lobj GFileInfo *file_info = NULL;

  memset (&data, 0, sizeof (data));
  
  root = (OstreeRepoFile*)ostree_repo_file_new_root (repo, resolved_commit);
  if (!ostree_repo_file_ensure_resolved (root, error))
    goto out;
  
  if (subpath)
    subtree = (OstreeRepoFile*)g_file_resolve_relative_path ((GFile*)root, subpath);
  else
    subtree = g_object_ref (root);

  file_info = g_file_query_info ((GFile*)subtree, OSTREE_GIO_FAST_QUERYINFO,
                                 G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
                                 cancellable, error);
  if (!file_info)
    goto out;

  data.loop = g_main_loop_new (NULL, TRUE);
  data.error = error;

  ostree_repo_checkout_tree_async (repo, opt_user_mode ? OSTREE_REPO_CHECKOUT_MODE_USER : 0,
                                   opt_union ? OSTREE_REPO_CHECKOUT_OVERWRITE_UNION_FILES : 0,
                                   target, subtree, file_info, cancellable,
                                   on_checkout_complete, &data);

  g_main_loop_run (data.loop);

  if (data.caught_error)
    goto out;
                      
  ret = TRUE;
 out:
  if (data.loop)
    g_main_loop_unref (data.loop);
  return ret;
}

static gboolean
process_many_checkouts (OstreeRepo         *repo,
                        GFile              *target,
                        GCancellable       *cancellable,
                        GError            **error)
{
  gboolean ret = FALSE;
  gsize len;
  GError *temp_error = NULL;
  ot_lobj GInputStream *instream = NULL;
  ot_lobj GDataInputStream *datastream = NULL;
  ot_lfree char *revision = NULL;
  ot_lfree char *subpath = NULL;
  ot_lfree char *resolved_commit = NULL;

  if (opt_from_stdin)
    {
      instream = (GInputStream*)g_unix_input_stream_new (0, FALSE);
    }
  else
    {
      ot_lobj GFile *f = g_file_new_for_path (opt_from_file);

      instream = (GInputStream*)g_file_read (f, cancellable, error);
      if (!instream)
        goto out;
    }
    
  datastream = g_data_input_stream_new (instream);

  while ((revision = g_data_input_stream_read_upto (datastream, "", 1, &len,
                                                    cancellable, &temp_error)) != NULL)
    {
      if (revision[0] == '\0')
        break;

      /* Read the null byte */
      (void) g_data_input_stream_read_byte (datastream, cancellable, NULL);
      g_free (subpath);
      subpath = g_data_input_stream_read_upto (datastream, "", 1, &len,
                                               cancellable, &temp_error);
      if (temp_error)
        {
          g_propagate_error (error, temp_error);
          goto out;
        }

      /* Read the null byte */
      (void) g_data_input_stream_read_byte (datastream, cancellable, NULL);

      if (!ostree_repo_resolve_rev (repo, revision, FALSE, &resolved_commit, error))
        goto out;

      if (!process_one_checkout (repo, resolved_commit, subpath, target,
                                 cancellable, error))
        {
          g_prefix_error (error, "Processing tree %s: ", resolved_commit);
          goto out;
        }

      g_free (revision);
    }
  if (temp_error)
    {
      g_propagate_error (error, temp_error);
      goto out;
    }

  ret = TRUE;
 out:
  return ret;
}

gboolean
ostree_builtin_checkout (int argc, char **argv, GFile *repo_path, GError **error)
{
  GOptionContext *context;
  GCancellable *cancellable = NULL;
  gboolean ret = FALSE;
  const char *commit;
  const char *destination;
  ot_lobj OstreeRepo *repo = NULL;
  ot_lfree char *existing_commit = NULL;
  ot_lfree char *resolved_commit = NULL;
  ot_lfree char *tmp_destination = NULL;
  ot_lobj GFileInfo *symlink_file_info = NULL;
  ot_lobj GFile *checkout_target = NULL;
  ot_lobj GFile *checkout_target_tmp = NULL;
  ot_lobj GFile *symlink_target = NULL;

  context = g_option_context_new ("COMMIT DESTINATION - Check out a commit into a filesystem tree");
  g_option_context_add_main_entries (context, options, NULL);

  if (!g_option_context_parse (context, &argc, &argv, error))
    goto out;

  repo = ostree_repo_new (repo_path);
  if (!ostree_repo_check (repo, error))
    goto out;

  if (argc < 2)
    {
      gchar *help = g_option_context_get_help (context, TRUE, NULL);
      g_printerr ("%s\n", help);
      g_free (help);
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "COMMIT must be specified");
      goto out;
    }

  if (opt_from_stdin || opt_from_file)
    {
      destination = argv[1];
      checkout_target = g_file_new_for_path (destination);

      if (!process_many_checkouts (repo, checkout_target, cancellable, error))
        goto out;
      
      if (!opt_no_triggers)
        {
          if (!ostree_run_triggers_in_root (checkout_target, cancellable, error))
            goto out;
        }
    }
  else
    {
      commit = argv[1];
      if (argc < 3)
        destination = commit;
      else
        destination = argv[2];

      if (!ostree_repo_resolve_rev (repo, commit, FALSE, &resolved_commit, error))
        goto out;

      checkout_target = g_file_new_for_path (destination);

      if (!process_one_checkout (repo, resolved_commit, opt_subpath,
                                 checkout_target_tmp ? checkout_target_tmp : checkout_target,
                                 cancellable, error))
        goto out;

      if (!opt_no_triggers)
        {
          if (!ostree_run_triggers_in_root (checkout_target_tmp ? checkout_target_tmp : checkout_target,
                                            cancellable, error))
            goto out;
        }
    }

  if (!ostree_repo_checkout_gc (repo, cancellable, error))
    goto out;

  ret = TRUE;
 out:
  if (context)
    g_option_context_free (context);
  return ret;
}
