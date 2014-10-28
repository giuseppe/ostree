/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2012 Colin Walters <walters@verbum.org>
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

#define LIBSOUP_USE_UNSTABLE_REQUEST_API
#include <libsoup/soup.h>
#include <libsoup/soup-requester.h>
#include <libsoup/soup-request-http.h>

G_BEGIN_DECLS

#define OSTREE_TYPE_FETCHER         (_ostree_fetcher_get_type ())
#define OSTREE_FETCHER(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), OSTREE_TYPE_FETCHER, OstreeFetcher))
#define OSTREE_FETCHER_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), OSTREE_TYPE_FETCHER, OstreeFetcherClass))
#define OSTREE_IS_FETCHER(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), OSTREE_TYPE_FETCHER))
#define OSTREE_IS_FETCHER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), OSTREE_TYPE_FETCHER))
#define OSTREE_FETCHER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), OSTREE_TYPE_FETCHER, OstreeFetcherClass))

typedef struct OstreeFetcherClass   OstreeFetcherClass;
typedef struct OstreeFetcher   OstreeFetcher;

struct OstreeFetcherClass
{
  GObjectClass parent_class;
};

typedef enum {
  OSTREE_FETCHER_FLAGS_NONE = 0,
  OSTREE_FETCHER_FLAGS_TLS_PERMISSIVE = (1 << 0)
} OstreeFetcherConfigFlags;

GType   _ostree_fetcher_get_type (void) G_GNUC_CONST;

OstreeFetcher *_ostree_fetcher_new (GFile                     *tmpdir,
                                   OstreeFetcherConfigFlags   flags);

void _ostree_fetcher_set_proxy (OstreeFetcher *fetcher,
                                const char    *proxy);

gboolean _ostree_fetcher_set_client_cert (OstreeFetcher *fetcher,
                                          const char *client_cert_path,
                                          const char *client_key_path,
                                          GError     **error);

void _ostree_fetcher_set_tls_database (OstreeFetcher *self,
                                       GTlsDatabase *db);

char * _ostree_fetcher_query_state_text (OstreeFetcher              *self);

guint64 _ostree_fetcher_bytes_transferred (OstreeFetcher       *self);

guint _ostree_fetcher_get_n_requests (OstreeFetcher       *self);

void _ostree_fetcher_request_uri_with_partial_async (OstreeFetcher         *self,
                                                    SoupURI               *uri,
                                                    guint64                max_size,
                                                    GCancellable          *cancellable,
                                                    GAsyncReadyCallback    callback,
                                                    gpointer               user_data);

GFile *_ostree_fetcher_request_uri_with_partial_finish (OstreeFetcher *self,
                                                       GAsyncResult  *result,
                                                       GError       **error);

void _ostree_fetcher_stream_uri_async (OstreeFetcher         *self,
                                      SoupURI               *uri,
                                      guint64                max_size,
                                      GCancellable          *cancellable,
                                      GAsyncReadyCallback    callback,
                                      gpointer               user_data);

GInputStream *_ostree_fetcher_stream_uri_finish (OstreeFetcher         *self,
                                                GAsyncResult          *result,
                                                GError               **error);

G_END_DECLS

#endif
