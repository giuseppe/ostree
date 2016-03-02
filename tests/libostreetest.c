/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2015 Red Hat, Inc.
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
#include <stdlib.h>
#include <string.h>

#include "libglnx.h"
#include "libostreetest.h"

/* This function hovers in a quantum superposition of horrifying and
 * beautiful.  Future generations may interpret it as modern art.
 */
static gboolean
run_libtest (const char *cmd, GError **error)
{
  gboolean ret = FALSE;
  const char *builddir = g_getenv ("G_TEST_BUILDDIR");
  int estatus;
  g_autoptr(GPtrArray) argv = g_ptr_array_new ();
  g_autoptr(GString) cmdstr = g_string_new ("");

  g_ptr_array_add (argv, "bash");
  g_ptr_array_add (argv, "-c");

  g_string_append (cmdstr, ". ");
  g_string_append (cmdstr, builddir);
  g_string_append (cmdstr, "/tests/libtest.sh; ");
  g_string_append (cmdstr, cmd);

  g_ptr_array_add (argv, cmdstr->str);
  g_ptr_array_add (argv, NULL);

  if (!g_spawn_sync (NULL, (char**)argv->pdata, NULL, G_SPAWN_SEARCH_PATH,
                     NULL, NULL, NULL, NULL, &estatus, error))
    goto out;

  if (!g_spawn_check_exit_status (estatus, error))
    goto out;

  ret = TRUE;
 out:
  return ret;
}

gboolean
ot_test_setup_repo (OtTest *self,
                    GCancellable *cancellable,
                    GError **error)
{
  gboolean ret = FALSE;
  g_autoptr(GFile) repo_path = g_file_new_for_path ("repo");

  if (!run_libtest ("setup_test_repository", error))
    goto out;

  self->repo = ostree_repo_new (repo_path);

  if (!ostree_repo_open (self->repo, cancellable, error))
    goto out;

  ret = TRUE;
 out:
  return ret;
}