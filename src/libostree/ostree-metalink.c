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

#include "config.h"

#include "ostree-metalink.h"
#include <gio/gfiledescriptorbased.h>

#include "otutil.h"

typedef enum {
  OSTREE_METALINK_STATE_INITIAL,
  OSTREE_METALINK_STATE_METALINK,
  OSTREE_METALINK_STATE_FILES,
  OSTREE_METALINK_STATE_FILE,
  OSTREE_METALINK_STATE_SIZE,
  OSTREE_METALINK_STATE_VERIFICATION,
  OSTREE_METALINK_STATE_HASH,
  OSTREE_METALINK_STATE_RESOURCES,
  OSTREE_METALINK_STATE_URL,

  OSTREE_METALINK_STATE_PASSTHROUGH /* Ignoring unknown elements */
} OstreeMetalinkState;

#define OSTREE_TYPE_METALINK         (_ostree_metalink_get_type ())
#define OSTREE_METALINK(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), OSTREE_TYPE_METALINK, OstreeMetalink))
#define OSTREE_METALINK_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), OSTREE_TYPE_METALINK, OstreeMetalinkClass))
#define OSTREE_IS_METALINK(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), OSTREE_TYPE_METALINK))
#define OSTREE_IS_METALINK_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), OSTREE_TYPE_METALINK))
#define OSTREE_METALINK_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), OSTREE_TYPE_METALINK, OstreeMetalinkClass))

struct OstreeMetalink
{
  GObject parent_instance;
  GTask *task;

  OstreeFetcher *fetcher;
  int priority;
  char *requested_file;
  guint64 max_size;

  guint64 size;
  char *verification_sha256;
  char *verification_sha512;

  guint current_url_index;
  GPtrArray *urls;
};

struct OstreeMetalinkClass
{
  GObjectClass parent_class;
};

typedef struct OstreeMetalinkClass   OstreeMetalinkClass;
typedef struct OstreeMetalink   OstreeMetalink;

GType   _ostree_metalink_get_type (void) G_GNUC_CONST;

G_DEFINE_TYPE (OstreeMetalink, _ostree_metalink, G_TYPE_OBJECT)

static void
_ostree_metalink_finalize (GObject *object)
{
  OstreeMetalink *self;

  self = OSTREE_METALINK (object);

  g_object_unref (self->task);
  g_object_unref (self->fetcher);
  g_free (self->requested_file);
  g_free (self->verification_sha256);
  g_free (self->verification_sha512);
  g_ptr_array_unref (self->urls);

  G_OBJECT_CLASS (_ostree_metalink_parent_class)->finalize (object);
}

static void
_ostree_metalink_class_init (OstreeMetalinkClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = _ostree_metalink_finalize;
}

static void
_ostree_metalink_init (OstreeMetalink *self)
{
}

typedef struct
{
  OstreeMetalink *metalink;

  guint passthrough_depth;
  OstreeMetalinkState passthrough_previous;

  guint found_a_file_element : 1;
  guint found_our_file_element : 1;
  guint verification_known : 1;

  GChecksumType in_verification_type;
  OstreeMetalinkState state;
} OstreeMetalinkParse;

static void
state_transition (OstreeMetalinkParse  *self,
                  OstreeMetalinkState   new_state)
{
  g_assert (self->state != new_state);

  if (new_state == OSTREE_METALINK_STATE_PASSTHROUGH)
    self->passthrough_previous = self->state;

  self->state = new_state;
}

static void
unknown_element (OstreeMetalinkParse           *self,
                 const char                    *element_name,
                 GError                       **error)
{
  state_transition (self, OSTREE_METALINK_STATE_PASSTHROUGH);
  g_assert (self->passthrough_depth == 0);
}

static void
metalink_parser_start (GMarkupParseContext  *context,
                       const gchar          *element_name,
                       const gchar         **attribute_names,
                       const gchar         **attribute_values,
                       gpointer              user_data,
                       GError              **error)
{
  OstreeMetalinkParse *self = user_data;

  switch (self->state)
    {
    case OSTREE_METALINK_STATE_INITIAL:
      if (strcmp (element_name, "metalink") == 0)
        state_transition (self, OSTREE_METALINK_STATE_METALINK);
      else
        unknown_element (self, element_name, error);
      break;
    case OSTREE_METALINK_STATE_METALINK:
      if (strcmp (element_name, "files") == 0)
        state_transition (self, OSTREE_METALINK_STATE_FILES);
      else
        unknown_element (self, element_name, error);
      break;
    case OSTREE_METALINK_STATE_FILES:
      /* If we've already processed a <file> element we're OK with, just
       * ignore the others.
       */
      if (self->metalink->urls->len > 0)
        {
          state_transition (self, OSTREE_METALINK_STATE_PASSTHROUGH);
        }
      else if (strcmp (element_name, "file") == 0)
        {
          const char *file_name;

          if (!g_markup_collect_attributes (element_name,
                                            attribute_names,
                                            attribute_values,
                                            error,
                                            G_MARKUP_COLLECT_STRING,
                                            "name",
                                            &file_name,
                                            G_MARKUP_COLLECT_INVALID))
            goto out;

          self->found_a_file_element = TRUE;

          if (strcmp (file_name, self->metalink->requested_file) != 0)
            {
              g_assert (self->passthrough_depth == 0);
              state_transition (self, OSTREE_METALINK_STATE_PASSTHROUGH);
            }
          else
            {
              self->found_our_file_element = TRUE;
              state_transition (self, OSTREE_METALINK_STATE_FILE);
            }
        }
      else
        unknown_element (self, element_name, error);
      break;
    case OSTREE_METALINK_STATE_FILE:
      if (strcmp (element_name, "size") == 0)
        state_transition (self, OSTREE_METALINK_STATE_SIZE);
      else if (strcmp (element_name, "verification") == 0)
        state_transition (self, OSTREE_METALINK_STATE_VERIFICATION);
      else if (strcmp (element_name, "resources") == 0)
        state_transition (self, OSTREE_METALINK_STATE_RESOURCES);
      else
        unknown_element (self, element_name, error);
      break;
    case OSTREE_METALINK_STATE_SIZE:
      unknown_element (self, element_name, error);
      break;
    case OSTREE_METALINK_STATE_VERIFICATION:
      if (strcmp (element_name, "hash") == 0)
        {
          char *verification_type_str = NULL;

          if (!g_markup_collect_attributes (element_name,
                                            attribute_names,
                                            attribute_values,
                                            error,
                                            G_MARKUP_COLLECT_STRING,
                                            "type",
                                            &verification_type_str,
                                            G_MARKUP_COLLECT_INVALID))
            goto out;

          /* Only accept sha256/sha512. */
          self->verification_known = TRUE;
          if (strcmp (verification_type_str, "sha256") == 0)
            self->in_verification_type = G_CHECKSUM_SHA256;
          else if (strcmp (verification_type_str, "sha512") == 0)
            self->in_verification_type = G_CHECKSUM_SHA512;
          else
            self->verification_known = FALSE;

          state_transition (self, OSTREE_METALINK_STATE_HASH);
        }
      else
        unknown_element (self, element_name, error);
      break;
    case OSTREE_METALINK_STATE_HASH:
      unknown_element (self, element_name, error);
      break;
    case OSTREE_METALINK_STATE_RESOURCES:
      if (self->metalink->size == 0)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "No <size> element found or it is zero");
          goto out;
        }
      if (!self->verification_known)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "No <verification> element with known <hash type=> found");
          goto out;
        }

      if (strcmp (element_name, "url") == 0)
        {
          const char *protocol;

          if (!g_markup_collect_attributes (element_name,
                                            attribute_names,
                                            attribute_values,
                                            error,
                                            G_MARKUP_COLLECT_STRING,
                                            "protocol",
                                            &protocol,
                                            G_MARKUP_COLLECT_STRING,
                                            "type",
                                            NULL,
                                            G_MARKUP_COLLECT_STRING,
                                            "location",
                                            NULL,
                                            G_MARKUP_COLLECT_STRING,
                                            "preference",
                                            NULL,
                                            G_MARKUP_COLLECT_INVALID))
            goto out;

          /* Ignore non-HTTP resources */
          if (!(strcmp (protocol, "http") == 0 || strcmp (protocol, "https") == 0))
            state_transition (self, OSTREE_METALINK_STATE_PASSTHROUGH);
          else
            state_transition (self, OSTREE_METALINK_STATE_URL);
        }
      else
        unknown_element (self, element_name, error);
      break;
    case OSTREE_METALINK_STATE_URL:
      unknown_element (self, element_name, error);
      break;
    case OSTREE_METALINK_STATE_PASSTHROUGH:
      self->passthrough_depth++;
      break;
    }

 out:
  return;
}

static void
metalink_parser_end (GMarkupParseContext  *context,
                     const gchar          *element_name,
                     gpointer              user_data,
                     GError              **error)
{
  OstreeMetalinkParse *self = user_data;

  switch (self->state)
    {
    case OSTREE_METALINK_STATE_INITIAL:
      break;
    case OSTREE_METALINK_STATE_METALINK:
      state_transition (self, OSTREE_METALINK_STATE_INITIAL);
      break;
    case OSTREE_METALINK_STATE_FILES:
      state_transition (self, OSTREE_METALINK_STATE_METALINK);
      break;
    case OSTREE_METALINK_STATE_FILE:
      state_transition (self, OSTREE_METALINK_STATE_FILES);
      break;
    case OSTREE_METALINK_STATE_SIZE:
    case OSTREE_METALINK_STATE_VERIFICATION:
    case OSTREE_METALINK_STATE_RESOURCES:
      state_transition (self, OSTREE_METALINK_STATE_FILE);
      break;
    case OSTREE_METALINK_STATE_HASH:
      state_transition (self, OSTREE_METALINK_STATE_VERIFICATION);
      break;
    case OSTREE_METALINK_STATE_URL:
      state_transition (self, OSTREE_METALINK_STATE_RESOURCES);
      break;
    case OSTREE_METALINK_STATE_PASSTHROUGH:
      if (self->passthrough_depth > 0)
        self->passthrough_depth--;
      else
        state_transition (self, self->passthrough_previous);
      break;
    }
}

static void
metalink_parser_text (GMarkupParseContext *context,
                      const gchar         *text,
                      gsize                text_len,
                      gpointer             user_data,
                      GError             **error)
{
  OstreeMetalinkParse *self = user_data;

  switch (self->state)
    {
    case OSTREE_METALINK_STATE_INITIAL:
      break;
    case OSTREE_METALINK_STATE_METALINK:
      break;
    case OSTREE_METALINK_STATE_FILES:
      break;
    case OSTREE_METALINK_STATE_FILE:
      break;
    case OSTREE_METALINK_STATE_SIZE:
      {
        g_autofree char *duped = g_strndup (text, text_len);
        self->metalink->size = g_ascii_strtoull (duped, NULL, 10);
      }
      break;
    case OSTREE_METALINK_STATE_VERIFICATION:
      break;
    case OSTREE_METALINK_STATE_HASH:
      if (self->verification_known)
        {
          switch (self->in_verification_type)
            {
            case G_CHECKSUM_SHA256:
              g_free (self->metalink->verification_sha256);
              self->metalink->verification_sha256 = g_strndup (text, text_len);
              break;
            case G_CHECKSUM_SHA512:
              g_free (self->metalink->verification_sha512);
              self->metalink->verification_sha512 = g_strndup (text, text_len);
              break;
            default:
              g_assert_not_reached ();
            }
        }
      break;
    case OSTREE_METALINK_STATE_RESOURCES:
      break;
    case OSTREE_METALINK_STATE_URL:
      {
        g_autofree char *uri_text = g_strndup (text, text_len);
        SoupURI *uri = soup_uri_new (uri_text);
        if (uri != NULL)
          g_ptr_array_add (self->metalink->urls, uri);
      }
      break;
    case OSTREE_METALINK_STATE_PASSTHROUGH:
      break;
    }

}

static const GMarkupParser metalink_parser = {
  metalink_parser_start,
  metalink_parser_end,
  metalink_parser_text,
  NULL,
  NULL
};

static gboolean
valid_hex_checksum (const char *s, gsize expected_len)
{
  gsize len = strspn (s, "01234567890abcdef");

  return len == expected_len && s[len] == '\0';
}

static void
try_one_url (GObject        *object,
             GAsyncResult   *result,
             gpointer        user_data)
{
  OstreeMetalink *self = (OstreeMetalink *)user_data;
  GError *local_error = NULL;
  GError **error = &local_error;
  g_autoptr(GBytes) bytes = NULL;
  gssize n_bytes;

  if (!_ostree_fetcher_stream_uri_finish (object, result, FALSE, FALSE, &bytes, g_task_get_cancellable (self->task), error))
    goto out;

  n_bytes = g_bytes_get_size (bytes);
  if (n_bytes != self->size)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Expected size is %" G_GUINT64_FORMAT " bytes but content is %" G_GSSIZE_FORMAT " bytes",
                   self->size, n_bytes);
      goto out;
    }

  if (self->verification_sha512)
    {
      g_autofree char *actual = NULL;

      actual = g_compute_checksum_for_bytes (G_CHECKSUM_SHA512, bytes);

      if (strcmp (self->verification_sha512, actual) != 0)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Expected checksum is %s but actual is %s",
                       self->verification_sha512, actual);
          goto out;
        }
    }
  else if (self->verification_sha256)
    {
      g_autofree char *actual = NULL;

      actual = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256, bytes);

      if (strcmp (self->verification_sha256, actual) != 0)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Expected checksum is %s but actual is %s",
                       self->verification_sha256, actual);
          goto out;
        }
    }

 out:
  if (local_error == NULL)
    {
      FetchMetalinkResult* out = g_new0(FetchMetalinkResult, 1);
      out->data = g_bytes_ref (bytes);
      out->target_uri = soup_uri_copy (self->urls->pdata[self->current_url_index]);
      g_task_return_pointer (self->task, out, g_free);
    }
  else
    {
      self->current_url_index++;
      if (self->current_url_index >= self->urls->len)
        {
          g_prefix_error (error,
                          "Exhausted %u metalink targets, last error: ",
                          self->urls->len);
          g_task_return_error (self->task, local_error);
        }
      else
        {
          g_clear_error (error);
          _ostree_fetcher_stream_uri_async (self->fetcher,
                                            self->urls->pdata[self->current_url_index],
                                            self->max_size,
                                            self->priority,
                                            g_task_get_cancellable(self->task),
                                            try_one_url,
                                            self);
        }
    }
}

static void
metalink_fetch_on_complete (GObject           *object,
                            GAsyncResult      *result,
                            gpointer           user_data)
{
  GError* local_error = NULL;
  GError **error = &local_error;
  OstreeMetalink *self = user_data;
  g_autoptr(GBytes) out_contents = NULL;
  gsize len;
  const guint8 *data;
  GMarkupParseContext *parser;
  OstreeMetalinkParse parse = { .metalink = self };

  if (!_ostree_fetcher_stream_uri_finish (object, result, FALSE, FALSE, &out_contents, g_task_get_cancellable(self->task), error))
    goto out;

  data = g_bytes_get_data (out_contents, &len);

  parser = g_markup_parse_context_new (&metalink_parser, G_MARKUP_PREFIX_ERROR_POSITION, &parse, NULL);
  if (!g_markup_parse_context_parse (parser, (const char*)data, len, error))
    goto out;
  g_markup_parse_context_free(parser);

  if (!parse.found_a_file_element)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "No <file> element found");
      goto out;
    }

  if (!parse.found_our_file_element)
    {
      /* XXX Use NOT_FOUND here so we can distinguish not finding the
       *     requested file from other errors.  This is a bit of a hack
       *     through; metalinks should have their own error enum. */
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                   "No <file name='%s'> found", self->requested_file);
      goto out;
    }

  if (!(self->verification_sha256 || self->verification_sha512))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "No <verification> hash for sha256 or sha512 found");
      goto out;
    }

  if (self->verification_sha256 && !valid_hex_checksum (self->verification_sha256, 64))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Invalid hash digest for sha256");
      goto out;
    }

  if (self->verification_sha512 && !valid_hex_checksum (self->verification_sha512, 128))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Invalid hash digest for sha512");
      goto out;
    }

  if (self->urls->len == 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "No <url method='http'> elements found");
      goto out;
    }

  self->current_url_index = 0;
  _ostree_fetcher_stream_uri_async (self->fetcher,
                                    self->urls->pdata[self->current_url_index],
                                    self->max_size,
                                    self->priority,
                                    g_task_get_cancellable(self->task),
                                    try_one_url,
                                    self);

 out:
  if (local_error != NULL)
    {
      g_task_return_error (self->task, local_error);
    }
}

void
_ostree_metalink_request_async (OstreeFetcher         *fetcher,
                                SoupURI               *uri,
                                const char            *requested_file,
                                guint64                max_size,
                                int                    priority,
                                GAsyncReadyCallback    callback,
                                gpointer               user_data,
                                GCancellable          *cancellable)
{
  glnx_unref_object OstreeMetalink *self = g_object_new (OSTREE_TYPE_METALINK, NULL);
  self->fetcher = g_object_ref (fetcher);
  self->requested_file = g_strdup (requested_file);
  self->max_size = max_size;
  self->priority = priority;
  self->task = g_task_new (self, cancellable, callback, user_data);
  g_task_set_source_tag (self->task, _ostree_metalink_request_async);
  self->urls = g_ptr_array_new_with_free_func ((GDestroyNotify) soup_uri_free);

  _ostree_fetcher_stream_uri_async (self->fetcher,
                                    uri,
                                    self->max_size,
                                    self->priority,
                                    cancellable,
                                    metalink_fetch_on_complete,
                                    self);
}

FetchMetalinkResult*
_ostree_metalink_request_finish (GObject          *self,
                                 GAsyncResult     *result,
                                 GError          **error)
{
  g_return_val_if_fail (g_task_is_valid (result, self), NULL);
  g_return_val_if_fail (g_async_result_is_tagged (result, _ostree_metalink_request_async), NULL);

  return g_task_propagate_pointer (G_TASK (result), error);
}
