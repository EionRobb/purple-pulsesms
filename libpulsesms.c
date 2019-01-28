/*
 * PulseSMS Plugin for libpurple/Pidgin
 * Copyright (c) 2015-2016 Eion Robb, Mike Ruprecht
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 

#define PULSESMS_PLUGIN_ID "prpl-eionrobb-pulsesms"
#define PULSESMS_PLUGIN_VERSION "0.1"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <json-glib/json-glib.h>

#if !GLIB_CHECK_VERSION(2, 32, 0)
#define g_hash_table_contains(hash_table, key) g_hash_table_lookup_extended(hash_table, key, NULL, NULL)
#endif /* 2.32.0 */

#include <purple.h>

#include "purplecompat.h"

#include <http.h>

// AES library from https://github.com/kokke/tiny-AES-c
#include "aes.h"

// Use purple's hmac-sha1 impl
int gc_hmac_sha1(const void *key, size_t keylen, const void *in, size_t inlen, void *resbuf);

// From https://github.com/gagern/gnulib/blob/master/lib/gc-pbkdf2-sha1.c
#include "gc-pbkdf2-sha1.c"

typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	PurpleHttpKeepalivePool *keepalive_pool;
	GHashTable *sent_message_ids;// A store of message id's that we generated from this instance
	
	struct AES_ctx* ctx;
	guint conv_fetch_timeout;
	gint64 last_conv_timestamp;
	
	GHashTable *im_conversations;     // conv_id -> phone number
	GHashTable *im_conversations_rev; // phone#  -> conv_id
	
	GHashTable *normalised_phone_lookup; // phone# -> id
	GHashTable *normalised_id_lookup; // id -> phone#
} PulseSMSAccount;


#ifdef ENABLE_NLS
#      define GETTEXT_PACKAGE "purple-pulsesms"
#      include <glib/gi18n-lib.h>
#	ifdef _WIN32
#		ifdef LOCALEDIR
#			unset LOCALEDIR
#		endif
#		define LOCALEDIR  wpurple_locale_dir()
#	endif
#else
#      define _(a) (a)
#      define N_(a) (a)
#endif

#define PULSESMS_API_HOST "https://api.messenger.klinkerapps.com"


static void pulsesms_create_ctx(PulseSMSAccount *psa);

/*****************************************************************************/

static gchar *
pulsesms_decrypt_len(PulseSMSAccount *psa, const gchar *data, gsize *len)
{
	if (data == NULL) {
		return NULL;
	}
	
	gchar **parts = g_strsplit(data, "-:-", 2);
	gsize text_len, iv_len;
	guchar *ciphertext = g_base64_decode(parts[1], &text_len);
	guchar *IV = g_base64_decode(parts[0], &iv_len);
	gsize buf_len = text_len + AES_BLOCKLEN - (text_len % AES_BLOCKLEN);
	
	guchar *buf = g_new0(guchar, buf_len);
	
	memcpy(buf, ciphertext, text_len);
	//XXX: does this need to be PKCS#7 padded?
	
	AES_ctx_set_iv(psa->ctx, IV);
	AES_CBC_decrypt_buffer(psa->ctx, buf, text_len);

	g_free(ciphertext);
	g_free(IV);
	g_strfreev(parts);
	
	//strip PKCS#5 padding
	buf[text_len - buf[text_len - 1]] = '\0';
	
	if (len != NULL) {
		*len = text_len;
	}
	
	return (gchar *) buf;
}


static gchar *
pulsesms_decrypt(PulseSMSAccount *psa, const gchar *data)
{
	return pulsesms_decrypt_len(psa, data, NULL);
}

// A reimplementation of gnulib's function, but using purple/glib functions
int
gc_hmac_sha1(const void *key, size_t keylen, const void *in, size_t inlen, void *resbuf)
{
#if PURPLE_VERSION_CHECK(3, 0, 0)
	GHmac *hmac;
	
	hmac = g_hmac_new(G_CHECKSUM_SHA1, key, keylen);
	g_hmac_update(hmac, in, inlen);
	g_hmac_get_digest(hmac, resbuf, 20);
	g_hmac_unref(hmac);
	
#else
	PurpleCipherContext *hmac;
	
	hmac = purple_cipher_context_new_by_name("hmac", NULL);

	purple_cipher_context_set_option(hmac, "hash", "sha1");
	purple_cipher_context_set_key_with_len(hmac, (guchar *)key, keylen);
	purple_cipher_context_append(hmac, (guchar *)in, inlen);
	purple_cipher_context_digest(hmac, 20, resbuf, NULL);
	purple_cipher_context_destroy(hmac);
	
#endif
	
	return 1;
}

JsonNode *
json_decode(const gchar *data, gssize len)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root = NULL;
	
	if (!data || !json_parser_load_from_data(parser, data, len, NULL))
	{
		purple_debug_error("pulsesms", "Error parsing JSON: %s\n", data);
	} else {
		root = json_parser_get_root(parser);
		if (root != NULL) {
			root = json_node_copy(root);
		}
	}
	g_object_unref(parser);
	
	return root;
}

JsonArray *
json_decode_array(const gchar *data, gssize len)
{
	JsonNode *root = json_decode(data, len);
	JsonArray *ret;
	
	g_return_val_if_fail(root, NULL);
	
	if (!JSON_NODE_HOLDS_ARRAY(root)) {
		// That ain't my belly button!
		json_node_free(root);
		return NULL;
	}

	ret = json_node_dup_array(root);

	json_node_free(root);
	
	return ret;
}

JsonObject *
json_decode_object(const gchar *data, gssize len)
{
	JsonNode *root = json_decode(data, len);
	JsonObject *ret;
	
	g_return_val_if_fail(root, NULL);
	
	if (!JSON_NODE_HOLDS_OBJECT(root)) {
		// That ain't my thumb, neither!
		json_node_free(root);
		return NULL;
	}
	
	ret = json_node_dup_object(root);

	json_node_free(root);

	return ret;
}


/*****************************************************************************/

static const char *
pulsesms_normalize(const PurpleAccount *account, const char *who)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	PulseSMSAccount *psa = pc ? purple_connection_get_protocol_data(pc) : NULL;
	
	// if (who[0] == '+') {
		// return who;
	// }
	
	if (!pc || !psa) {
		return who;
	}
	
	const gchar *normalised_id = g_hash_table_lookup(psa->normalised_phone_lookup, who);
	if (normalised_id) {
		const gchar *normalised_phone = g_hash_table_lookup(psa->normalised_id_lookup, normalised_id);
		if (normalised_phone) {
			return normalised_phone;
		}
	}
	
	return who;
}

static int
pulsesms_send_im(PurpleConnection *pc,
#if PURPLE_VERSION_CHECK(3, 0, 0)
				PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
				const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif
	GString *postbody;
	PulseSMSAccount *psa = purple_connection_get_protocol_data(pc);
	gchar *stripped_message;
	
	PurpleHttpRequest *request = purple_http_request_new(PULSESMS_API_HOST "/api/v1/messages/forward_to_phone");
	purple_http_request_set_keepalive_pool(request, psa->keepalive_pool);
	
	purple_http_request_set_method(request, "POST");
	purple_http_request_header_set(request, "Content-type", "application/x-www-form-urlencoded; charset=UTF-8");
	
	stripped_message = g_strstrip(purple_markup_strip_html(message));
	
	postbody = g_string_new(NULL);
	g_string_append_printf(postbody, "account_id=%s&", purple_url_encode(purple_account_get_string(psa->account, "account_id", "")));
	g_string_append_printf(postbody, "to=%s&", purple_url_encode(who));
	g_string_append_printf(postbody, "message=%s&", purple_url_encode(stripped_message));
	g_string_append_printf(postbody, "sent_device=3&"); //Native client
	purple_http_request_set_contents(request, postbody->str, postbody->len);
	g_string_free(postbody, TRUE);
	
	purple_http_request(psa->pc, request, NULL, NULL);
	purple_http_request_unref(request);
	
	g_free(stripped_message);
	return 1;
}

static void
pulsesms_got_contacts(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	PulseSMSAccount *psa = user_data;
	gsize len;
	const gchar *data = purple_http_response_get_data(response, &len);
	JsonArray *contacts = json_decode_array(data, len);
	int i;
	
	PurpleGroup *group = purple_blist_find_group("PulseSMS");

	if (!group) {
		group = purple_group_new("PulseSMS");
		purple_blist_add_group(group, NULL);
	}

	for (i = json_array_get_length(contacts) - 1; i >= 0; i--) {
		JsonObject *contact = json_array_get_object_element(contacts, i);
		
		gchar *phone_number = pulsesms_decrypt(psa, json_object_get_string_member(contact, "phone_number"));
		gchar *name = pulsesms_decrypt(psa, json_object_get_string_member(contact, "name"));
		gchar *id_matcher = pulsesms_decrypt(psa, json_object_get_string_member(contact, "id_matcher"));
		
		purple_debug_info("pulsesms", "phone_number: %s, name: %s, id_matcher: %s\n", phone_number, name, id_matcher);
		
		//TODO use this to join contacts together with their international number equivalents
		g_hash_table_insert(psa->normalised_phone_lookup, g_strdup(phone_number), g_strdup(id_matcher));
		if (phone_number[0] == '+' || purple_strequal(id_matcher, phone_number)) {
			g_hash_table_insert(psa->normalised_id_lookup, g_strdup(id_matcher), g_strdup(phone_number));
		}
		
		PurpleBuddy *buddy = purple_blist_find_buddy(psa->account, phone_number);

		if (buddy == NULL) {
			buddy = purple_buddy_new(psa->account, phone_number, name);
			purple_blist_add_buddy(buddy, NULL, group, NULL);
		}
		
		purple_protocol_got_user_status(psa->account, phone_number, "mobile", NULL);
	}
}

static void
pulsesms_fetch_contacts(PulseSMSAccount *psa)
{
	const gchar *account_id = purple_account_get_string(psa->account, "account_id", NULL);
	
	PurpleHttpRequest *request = purple_http_request_new(NULL);
	purple_http_request_set_keepalive_pool(request, psa->keepalive_pool);
	
	purple_http_request_set_url_printf(request, PULSESMS_API_HOST "/api/v1/contacts/simple?account_id=%s", purple_url_encode(account_id));
	
	purple_http_request(psa->pc, request, pulsesms_got_contacts, psa);
	purple_http_request_unref(request);
}

static void
pulsesms_got_http_image_for_conv(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	PulseSMSAccount *psa = user_data;
	PurpleHttpRequest *request = purple_http_conn_get_request(http_conn);
	const gchar *phone_number = g_dataset_get_data(request, "phone_number");
	gint message_type = GPOINTER_TO_INT(g_dataset_get_data(request, "message_type"));
	gint timestamp = GPOINTER_TO_INT(g_dataset_get_data(request, "timestamp"));
	gsize len;
	const gchar *data = purple_http_response_get_data(response, &len);
	PurpleImage *image;
	guint image_id;
	gchar *image_message;
	
	if (purple_http_response_get_error(response) != NULL) {
		g_dataset_destroy(request);
		return;
	}
	
	gsize image_len;
	gchar *image_data = pulsesms_decrypt_len(psa, data, &image_len);
	
	image = purple_image_new_from_data(image_data, image_len);
	image_id = purple_image_store_add(image);
	image_message = g_strdup_printf("<img id='%ud' />", image_id);
	
	if (message_type == 0) {
		purple_serv_got_im(psa->pc, phone_number, image_message, PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_IMAGES, timestamp);
		
	} else if (message_type == 1 || message_type == 2) {
		PurpleConversation *conv;
		PurpleIMConversation *imconv;
		PurpleMessage *msg;

		imconv = purple_conversations_find_im_with_account(phone_number, psa->account);

		if (imconv == NULL) {
			imconv = purple_im_conversation_new(psa->account, phone_number);
		}

		conv = PURPLE_CONVERSATION(imconv);

		msg = purple_message_new_outgoing(phone_number, image_message, PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED | PURPLE_MESSAGE_IMAGES);
		purple_message_set_time(msg, timestamp);
		purple_conversation_write_message(conv, msg);
		purple_message_destroy(msg);
	}
	
	g_free(image_message);
	g_dataset_destroy(request);
}

static void
pulsesms_got_conversation_history(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	PulseSMSAccount *psa = user_data;
	PurpleHttpRequest *request = purple_http_conn_get_request(http_conn);
	gchar *conv_id_str = g_dataset_get_data(request, "conv_id");
	gchar *since_str = g_dataset_get_data(request, "since");
	gsize len;
	gint i;
	const gchar *data = purple_http_response_get_data(response, &len);
	JsonArray *messages = json_decode_array(data, len);
	gint64 conv_id = g_ascii_strtoll(conv_id_str, NULL, 10);
	gint64 since = g_ascii_strtoll(since_str, NULL, 10);
	const gchar *phone_number = g_hash_table_lookup(psa->im_conversations, &conv_id);
	
	if (phone_number == NULL) {
		purple_debug_error("pulsesms", "Error, unknown conversation id %s\n", conv_id_str);
		
		// use /api/v1/conversations/" conv_id "?account_id=... to lookup unknown conv ids
		
		g_dataset_destroy(request);
		g_free(conv_id_str);
		g_free(since_str);
		return;
	}
	
	for (i = json_array_get_length(messages) - 1; i >= 0; i--) {
		JsonObject *message = json_array_get_object_element(messages, i);
		gint64 message_type = json_object_get_int_member(message, "message_type");
		gchar *data = pulsesms_decrypt(psa, json_object_get_string_member(message, "data"));
		gchar *escaped_data = purple_markup_escape_text(data, -1);
		gint64 timestamp = json_object_get_int_member(message, "timestamp");
		gchar *mime_type = pulsesms_decrypt(psa, json_object_get_string_member(message, "mime_type"));
		
		  //if (message.message_type == 0) { // received or media
		  //} else if (message.message_type == 6) {  //media preview
		  //} else if (message.message_type == 3) {  //error
		  //} else if (message.message_type == 5) {  //info
			//} else {  //sent message   (2 sending, 1 sent, 4 delivered)
		if (timestamp > since) {
			if (mime_type && strncmp(mime_type, "image/", 6) == 0) {
				gint64 message_id = json_object_get_int_member(message, "device_id");
				PurpleHttpRequest *request = purple_http_request_new(NULL);
				const gchar *account_id = purple_account_get_string(psa->account, "account_id", NULL);
				
				purple_http_request_set_url_printf(request, PULSESMS_API_HOST "/api/v1/media/%" G_GINT64_FORMAT "?account_id=%s", message_id, purple_url_encode(account_id));
				
				g_dataset_set_data(request, "message_type", GINT_TO_POINTER((int) message_type));
				g_dataset_set_data(request, "timestamp", GINT_TO_POINTER((int) (timestamp / 1000)));
				g_dataset_set_data_full(request, "phone_number", g_strdup(phone_number), g_free);
				purple_http_request_set_max_len(request, -1);
				purple_http_request_header_set(request, "Accept-Encoding", " "); // Disable compression to disable crashing
				purple_http_request(psa->pc, request, pulsesms_got_http_image_for_conv, psa);
				purple_http_request_unref(request);
				
			} else {
				if (message_type == 0) {
					purple_serv_got_im(psa->pc, phone_number, escaped_data, PURPLE_MESSAGE_RECV, timestamp / 1000);
					
				} else if (message_type == 1 || message_type == 2) {
					PurpleConversation *conv;
					PurpleIMConversation *imconv;
					PurpleMessage *msg;

					imconv = purple_conversations_find_im_with_account(phone_number, psa->account);

					if (imconv == NULL) {
						imconv = purple_im_conversation_new(psa->account, phone_number);
					}

					conv = PURPLE_CONVERSATION(imconv);

					if (escaped_data && *escaped_data) {
						msg = purple_message_new_outgoing(phone_number, escaped_data, PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED);
						purple_message_set_time(msg, timestamp / 1000);
						purple_conversation_write_message(conv, msg);
						purple_message_destroy(msg);
					}
				}
				
			}
		}
		
		g_free(data);
		g_free(escaped_data);
  
	}
	
	g_dataset_destroy(request);
	g_free(conv_id_str);
	g_free(since_str);
}

static void
pulsesms_fetch_conversation_history(PulseSMSAccount *psa, gint64 conv_id, gint64 since)
{
	const gchar *account_id = purple_account_get_string(psa->account, "account_id", NULL);
	
	PurpleHttpRequest *request = purple_http_request_new(NULL);
	purple_http_request_set_keepalive_pool(request, psa->keepalive_pool);
	
	purple_http_request_set_url_printf(request, PULSESMS_API_HOST "/api/v1/messages?account_id=%s&conversation_id=%" G_GINT64_FORMAT "&limit=20", purple_url_encode(account_id), conv_id);
	
	g_dataset_set_data(request, "conv_id", g_strdup_printf("%" G_GINT64_FORMAT, conv_id));
	g_dataset_set_data(request, "since", g_strdup_printf("%" G_GINT64_FORMAT, since));
	purple_http_request(psa->pc, request, pulsesms_got_conversation_history, psa);
	purple_http_request_unref(request);
}

static void
pulsesms_got_conversations(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	PulseSMSAccount *psa = user_data;
	gsize len;
	const gchar *data = purple_http_response_get_data(response, &len);
	JsonArray *conversations = json_decode_array(data, len);
	int i;
	gint64 max_timestamp = 0;

	for (i = json_array_get_length(conversations) - 1; i >= 0; i--) {
		JsonObject *conversation = json_array_get_object_element(conversations, i);
		
		gint64 conv_id = json_object_get_int_member(conversation, "device_id");
		gchar *phone_number = pulsesms_decrypt(psa, json_object_get_string_member(conversation, "phone_numbers"));
		gint64 timestamp = json_object_get_int_member(conversation, "timestamp");
		
		//purple_debug_misc("pulsesms", "Phone number %s conv_id %" G_GINT64_FORMAT " timestamp %" G_GINT64_FORMAT "\n", phone_number, conv_id, timestamp);
		
		if (timestamp > max_timestamp) {
			max_timestamp = timestamp;
		}
		if (psa->last_conv_timestamp && timestamp > psa->last_conv_timestamp) {
			if (!g_hash_table_contains(psa->im_conversations, &conv_id)) {
				g_hash_table_insert(psa->im_conversations, g_memdup(&conv_id, sizeof(gint64)), g_strdup(phone_number));
				g_hash_table_insert(psa->im_conversations_rev, g_strdup(phone_number), GUINT_TO_POINTER((guint) conv_id));
			}
			
			pulsesms_fetch_conversation_history(psa, conv_id, psa->last_conv_timestamp);
		}
		
		g_free(phone_number);
	}
	
	if (max_timestamp != 0) {
		psa->last_conv_timestamp = max_timestamp;
		
		purple_account_set_int(psa->account, "last_conv_timestamp_high", max_timestamp >> 32);
		purple_account_set_int(psa->account, "last_conv_timestamp_low", max_timestamp & 0xFFFFFFFF);
	}
}

static gboolean
pulsesms_fetch_conversations(gpointer data)
{
	PulseSMSAccount *psa = data;
	const gchar *account_id = purple_account_get_string(psa->account, "account_id", NULL);
	
	PurpleHttpRequest *request = purple_http_request_new(NULL);
	purple_http_request_set_keepalive_pool(request, psa->keepalive_pool);
	
	purple_http_request_set_url_printf(request, PULSESMS_API_HOST "/api/v1/conversations/index_public_unarchived?account_id=%s", purple_url_encode(account_id));
	
	purple_http_request(psa->pc, request, pulsesms_got_conversations, psa);
	purple_http_request_unref(request);
	
	return TRUE;
}

static void
pulsesms_start_stuff(PulseSMSAccount *psa)
{
	//TODO
	//wss://api.messenger.klinkerapps.com/api/v1/stream?account_id=
	
	
	pulsesms_create_ctx(psa);
	pulsesms_fetch_contacts(psa);
	
	pulsesms_fetch_conversations(psa);
	psa->conv_fetch_timeout = g_timeout_add_seconds(60, pulsesms_fetch_conversations, psa);
	
	purple_connection_set_state(psa->pc, PURPLE_CONNECTION_CONNECTED);
}

static void
pulsesms_got_login(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	PulseSMSAccount *psa = user_data;
	gsize len;
	const gchar *data = purple_http_response_get_data(response, &len);
	JsonObject *info = json_decode_object(data, len);
	
	purple_account_set_string(psa->account, "account_id", json_object_get_string_member(info, "account_id"));
	purple_account_set_string(psa->account, "salt", json_object_get_string_member(info, "salt1"));
	
	const gchar *password = purple_connection_get_password(psa->pc);
	const gchar *salt2 = json_object_get_string_member(info, "salt2");
	unsigned dklen = 32;
	unsigned rounds = 10000;
	uint8_t DK[ dklen ];
	
	gc_pbkdf2_sha1(password, strlen(password), salt2, strlen(salt2), rounds, (char*) DK, dklen);
	
	gchar *hash = g_base64_encode(DK, dklen);
	
	purple_account_set_string(psa->account, "hash", hash);
	
	g_free(hash);
	
	pulsesms_start_stuff(psa);
}

static void
pulsesms_send_login(PulseSMSAccount *psa)
{
	GString *postbody;
	
	PurpleHttpRequest *request = purple_http_request_new(PULSESMS_API_HOST "/api/v1/accounts/login");
	purple_http_request_set_keepalive_pool(request, psa->keepalive_pool);
	
	purple_http_request_set_method(request, "POST");
	purple_http_request_header_set(request, "Content-type", "application/x-www-form-urlencoded; charset=UTF-8");
	
	postbody = g_string_new(NULL);
	g_string_append_printf(postbody, "username=%s&", purple_url_encode(purple_account_get_username(psa->account)));
	g_string_append_printf(postbody, "password=%s&", purple_url_encode(purple_connection_get_password(psa->pc)));
	purple_http_request_set_contents(request, postbody->str, postbody->len);
	g_string_free(postbody, TRUE);
	
	purple_http_request(psa->pc, request, pulsesms_got_login, psa);
	purple_http_request_unref(request);
}

/*****************************************************************************/


static GList *
pulsesms_add_account_options(GList *account_options)
{
	// PurpleAccountOption *option;
	
	// option = purple_account_option_bool_new(N_("Show call links in chat"), "show-call-links", !purple_media_manager_get());
	// account_options = g_list_append(account_options, option);
	
	// option = purple_account_option_bool_new(N_("Un-Googlify URLs"), "unravel_google_url", FALSE);
	// account_options = g_list_append(account_options, option);
	
	// option = purple_account_option_bool_new(N_("Treat invisible users as offline"), "treat_invisible_as_offline", FALSE);
	// account_options = g_list_append(account_options, option);
	
	return account_options;
}

static GList *
pulsesms_actions(
#if !PURPLE_VERSION_CHECK(3, 0, 0)
PurplePlugin *plugin, gpointer context
#else
PurpleConnection *pc
#endif
)
{
	GList *m = NULL;
	// PurpleProtocolAction *act;

	// act = purple_protocol_action_new(_("Search for friends..."), pulsesms_search_users);
	// m = g_list_append(m, act);

	// act = purple_protocol_action_new(_("Join a group chat by URL..."), pulsesms_join_chat_by_url_action);
	// m = g_list_append(m, act);

	return m;
}

static void
pulsesms_create_ctx(PulseSMSAccount *psa)
{
	const gchar *account_id = purple_account_get_string(psa->account, "account_id", NULL);
	const gchar *hash = purple_account_get_string(psa->account, "hash", NULL);
	const gchar *salt = purple_account_get_string(psa->account, "salt", NULL);
	
	gchar *combined_key = g_strdup_printf("%s:%s\n", account_id, hash);
	
	unsigned dklen = 32;
	unsigned rounds = 10000;
	uint8_t DK[ dklen ];
	
	gc_pbkdf2_sha1(combined_key, strlen(combined_key), salt, strlen(salt), rounds, (char*) DK, dklen);

	AES_init_ctx(psa->ctx, DK);
	
	g_free(combined_key);
}

static void
pulsesms_login(PurpleAccount *account)
{
	PurpleConnection *pc;
	PulseSMSAccount *psa;
	const gchar *password;
	// PurpleConnectionFlags pc_flags;

	pc = purple_account_get_connection(account);
	password = purple_connection_get_password(pc);
	
	// pc_flags = purple_connection_get_flags(pc);
	// pc_flags |= PURPLE_CONNECTION_FLAG_HTML;
	// pc_flags |= PURPLE_CONNECTION_FLAG_NO_FONTSIZE;
	// pc_flags |= PURPLE_CONNECTION_FLAG_NO_BGCOLOR;
	// pc_flags &= ~PURPLE_CONNECTION_FLAG_NO_IMAGES;
	// purple_connection_set_flags(pc, pc_flags);
	
	psa = g_new0(PulseSMSAccount, 1);
	psa->account = account;
	psa->pc = pc;
	psa->keepalive_pool = purple_http_keepalive_pool_new();
	psa->sent_message_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	psa->im_conversations = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
	psa->im_conversations_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	psa->normalised_phone_lookup = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	psa->normalised_id_lookup = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	psa->ctx = g_new0(struct AES_ctx, 1);
	
	psa->last_conv_timestamp = purple_account_get_int(account, "last_conv_timestamp_high", 0);
	if (psa->last_conv_timestamp != 0) {
		psa->last_conv_timestamp = (psa->last_conv_timestamp << 32) | ((gint64) purple_account_get_int(account, "last_conv_timestamp_low", 0) & 0xFFFFFFFF);
	}
	
	purple_connection_set_protocol_data(pc, psa);
	
	if (purple_account_get_string(account, "account_id", NULL) && 
		purple_account_get_string(account, "hash", NULL) &&
		purple_account_get_string(account, "salt", NULL)) {
		
		pulsesms_start_stuff(psa);
	} else if (password && *password) {
		purple_connection_update_progress(pc, _("Authenticating"), 1, 3);
		pulsesms_send_login(psa);
	}
}

static void
pulsesms_close(PurpleConnection *pc)
{
	PulseSMSAccount *psa;
	
	psa = purple_connection_get_protocol_data(pc);
	purple_signals_disconnect_by_handle(psa->account);
	
	if (psa->conv_fetch_timeout) {
		g_source_remove(psa->conv_fetch_timeout);
	}
	
	purple_http_conn_cancel_all(pc);
	
	purple_http_keepalive_pool_unref(psa->keepalive_pool);
	
	g_hash_table_remove_all(psa->sent_message_ids);
	g_hash_table_unref(psa->sent_message_ids);
	
	g_hash_table_remove_all(psa->im_conversations);
	g_hash_table_unref(psa->im_conversations);
	g_hash_table_remove_all(psa->im_conversations_rev);
	g_hash_table_unref(psa->im_conversations_rev);
	
	g_hash_table_remove_all(psa->normalised_phone_lookup);
	g_hash_table_unref(psa->normalised_phone_lookup);
	psa->normalised_phone_lookup = NULL;
	g_hash_table_remove_all(psa->normalised_id_lookup);
	g_hash_table_unref(psa->normalised_id_lookup);
	psa->normalised_id_lookup = NULL;
	
	g_free(psa->ctx);
	
	g_free(psa);
}


static const char *
pulsesms_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "pulsesms";
}

GList *
pulsesms_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;
	
	status = purple_status_type_new_full(PURPLE_STATUS_MOBILE, "mobile", _("Phone"), FALSE, FALSE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;
}

static gboolean
pulsesms_offline_message(const PurpleBuddy *buddy)
{
	return TRUE;
}


/*****************************************************************************/

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);
	
	return TRUE;
}

#if PURPLE_VERSION_CHECK(3, 0, 0)

G_MODULE_EXPORT GType pulsesms_protocol_get_type(void);
#define PULSESMS_TYPE_PROTOCOL			(pulsesms_protocol_get_type())
#define PULSESMS_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), PULSESMS_TYPE_PROTOCOL, PulseSMSProtocol))
#define PULSESMS_PROTOCOL_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), PULSESMS_TYPE_PROTOCOL, PulseSMSProtocolClass))
#define PULSESMS_IS_PROTOCOL(obj)		(G_TYPE_CHECK_INSTANCE_TYPE((obj), PULSESMS_TYPE_PROTOCOL))
#define PULSESMS_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), PULSESMS_TYPE_PROTOCOL))
#define PULSESMS_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), PULSESMS_TYPE_PROTOCOL, PulseSMSProtocolClass))

typedef struct _PulseSMSProtocol
{
	PurpleProtocol parent;
} PulseSMSProtocol;

typedef struct _PulseSMSProtocolClass
{
	PurpleProtocolClass parent_class;
} PulseSMSProtocolClass;

static void
pulsesms_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *plugin = prpl_info, *info = prpl_info;

	info->id = PULSESMS_PLUGIN_ID;
	info->name = "PulseSMS";

	prpl_info->account_options = pulsesms_add_account_options(prpl_info->account_options);
}

static void
pulsesms_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = pulsesms_login;
	prpl_info->close = pulsesms_close;
	prpl_info->status_types = pulsesms_status_types;
	prpl_info->list_icon = pulsesms_list_icon;
}

static void
pulsesms_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
 	prpl_info->offline_message = pulsesms_offline_message;
}

static void 
pulsesms_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = pulsesms_send_im;
}

static PurpleProtocol *pulsesms_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	PulseSMSProtocol, pulsesms_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  pulsesms_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
	                                  pulsesms_protocol_client_iface_init)
);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	pulsesms_protocol_register_type(plugin);
	pulsesms_protocol = purple_protocols_add(PULSESMS_TYPE_PROTOCOL, error);
	if (!pulsesms_protocol)
		return FALSE;

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(pulsesms_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          PULSESMS_PLUGIN_ID,
		"name",        "PulseSMS",
		"version",     PULSESMS_PLUGIN_VERSION,
		"category",    N_("Protocol"),
		"summary",     N_("PulseSMS Protocol Plugins."),
		"description", N_("Adds SMS support (via Pulse SMS) to libpurple."),
		"website",     "https://bitbucket.org/EionRobb/purple-pulsesms/",
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(pulsesms, plugin_query,
		libpurple3_plugin_load, libpurple3_plugin_unload);

#else
	
// Normally set in core.c in purple3
void _purple_socket_init(void);
void _purple_socket_uninit(void);


static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	_purple_socket_init();
	purple_http_init();
	
	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	_purple_socket_uninit();
	purple_http_uninit();
	
	return plugin_unload(plugin, NULL);
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                             /**< type           */
	NULL,                                               /**< ui_requirement */
	0,                                                  /**< flags          */
	NULL,                                               /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */

	PULSESMS_PLUGIN_ID,                                 /**< id             */
	N_("PulseSMS"),                                     /**< name           */
	PULSESMS_PLUGIN_VERSION,                            /**< version        */
	                                 
	N_("PulseSMS Protocol Plugins."),                   /**< summary        */
	                                                  
	N_("Adds SMS support (via Pulse SMS) to libpurple."), /**< description    */
	"Eion Robb <eionrobb+pulsesms@gmail.com>",          /**< author         */
	"https://bitbucket.org/EionRobb/purple-pulsesms/",  /**< homepage       */

	libpurple2_plugin_load,                             /**< load           */
	libpurple2_plugin_unload,                           /**< unload         */
	NULL,                                               /**< destroy        */

	NULL,                                               /**< ui_info        */
	NULL,                                               /**< extra_info     */
	NULL,                                               /**< prefs_info     */
	NULL,                                               /**< actions        */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);
	
	info = plugin->info;
	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}

	prpl_info->protocol_options = pulsesms_add_account_options(prpl_info->protocol_options);
	
	prpl_info->login = pulsesms_login;
	prpl_info->close = pulsesms_close;
	prpl_info->status_types = pulsesms_status_types;
	prpl_info->list_icon = pulsesms_list_icon;
	prpl_info->offline_message = pulsesms_offline_message;
	prpl_info->normalize = pulsesms_normalize;
	
	prpl_info->send_im = pulsesms_send_im;
	
	info->extra_info = prpl_info;
	#if PURPLE_MINOR_VERSION >= 5
		prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
	#endif
	
	info->actions = pulsesms_actions;
}
	
PURPLE_INIT_PLUGIN(pulsesms, init_plugin, info);

#endif