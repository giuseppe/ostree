/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2014 Colin Walters <walters@verbum.org>
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

#pragma once

#ifndef __GI_SCANNER__

#include "ostree-fetcher.h"

G_BEGIN_DECLS

void
_ostree_metalink_request_async (OstreeFetcher         *fetcher,
                                SoupURI               *uri,
                                const char            *requested_file,
                                guint64                max_size,
                                int                    priority,
                                GAsyncReadyCallback    callback,
                                gpointer               user_data,
                                GCancellable          *cancellable);

typedef struct
{
  SoupURI               *target_uri;
  GBytes                *data;
} FetchMetalinkResult;

FetchMetalinkResult*
_ostree_metalink_request_finish (GObject               *object,
                                 GAsyncResult          *result,
                                 GError               **error);


G_END_DECLS

#endif
