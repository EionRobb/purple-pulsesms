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

#include <purple.h>

#include "purplecompat.h"

#include <http.h>

// AES library from https://github.com/kokke/tiny-AES-c
#define ECB 0
#define CTR 0
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
} PulseSMSAccount;


#ifdef ENABLE_NLS
#      define GETTEXT_PACKAGE "purple-discord"
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
pulsesms_decrypt(PulseSMSAccount *psa, const gchar *data)
{
	gchar **parts = g_strsplit(data, "-:-", 2);
	gsize text_len, iv_len;
	guchar *ciphertext = g_base64_decode(parts[1], &text_len);
	guchar *IV = g_base64_decode(parts[0], &iv_len);
	gsize buf_len = text_len + AES_BLOCKLEN - (text_len % AES_BLOCKLEN);
	
	guchar *buf = g_new0(guchar, buf_len);
	
	memcpy(buf, ciphertext, text_len);
	
	AES_ctx_set_iv(psa->ctx, IV);
	AES_CBC_decrypt_buffer(psa->ctx, buf, text_len);

	g_free(ciphertext);
	g_free(IV);
	g_strfreev(parts);
	
	return (gchar *) buf;
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
		purple_debug_error("hangouts", "Error parsing JSON: %s\n", data);
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
	
	PurpleHttpRequest *request = purple_http_request_new(PULSESMS_API_HOST "/api/v1/messages/forward_to_phone");
	purple_http_request_set_keepalive_pool(request, psa->keepalive_pool);
	
	purple_http_request_set_method(request, "POST");
	purple_http_request_header_set(request, "Content-type", "application/x-www-form-urlencoded; charset=UTF-8");
	
	postbody = g_string_new(NULL);
	g_string_append_printf(postbody, "account_id=%s&", purple_url_encode(purple_account_get_string(psa->account, "account_id", "")));
	g_string_append_printf(postbody, "to=%s&", purple_url_encode(who));
	g_string_append_printf(postbody, "message=%s&", purple_url_encode(message));
	g_string_append_printf(postbody, "sent_device=0&");
	purple_http_request_set_contents(request, postbody->str, postbody->len);
	g_string_free(postbody, TRUE);
	
	purple_http_request(psa->pc, request, NULL, NULL);
	purple_http_request_unref(request);
	
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

	for (i = json_array_get_length(contacts) - 1; i >= 0; i--) {
		JsonObject *contact = json_array_get_object_element(contacts, i);
		
		gchar *phone_number = pulsesms_decrypt(psa, json_object_get_string_member(contact, "phone_number"));
		gchar *name = pulsesms_decrypt(psa, json_object_get_string_member(contact, "name"));
		gchar *id_matcher = pulsesms_decrypt(psa, json_object_get_string_member(contact, "id_matcher"));
		
		purple_debug_info("pulsesms", "phone_number: %s, name: %s, id_matcher: %s\n", phone_number, name, id_matcher);
		
		break;
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
	unsigned dklen = 30;
	unsigned rounds = 10000;
	uint8_t DK[ dklen ];
	
	gc_pbkdf2_sha1(password, strlen(password), salt2, strlen(salt2), rounds, (char*) DK, dklen);
	
	gchar *hash = g_base64_encode(DK, dklen);
	
	purple_account_set_string(psa->account, "hash", hash);
	
	g_free(hash);
	
	
	pulsesms_create_ctx(psa);
	pulsesms_fetch_contacts(psa);
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
	
	unsigned dklen = 30;
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
	psa->ctx = g_new0(struct AES_ctx, 1);
	
	purple_connection_set_protocol_data(pc, psa);
	
	if (purple_account_get_string(account, "account_id", NULL) && 
		purple_account_get_string(account, "hash", NULL) &&
		purple_account_get_string(account, "salt", NULL)) {
		
		pulsesms_create_ctx(psa);
		pulsesms_fetch_contacts(psa);
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
	
	purple_http_conn_cancel_all(pc);
	
	purple_http_keepalive_pool_unref(psa->keepalive_pool);
	
	g_hash_table_remove_all(psa->sent_message_ids);
	g_hash_table_unref(psa->sent_message_ids);
	
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
	
	prpl_info->send_im = pulsesms_send_im;
	
	info->extra_info = prpl_info;
	#if PURPLE_MINOR_VERSION >= 5
		prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
	#endif
	
	info->actions = pulsesms_actions;
}
	
PURPLE_INIT_PLUGIN(pulsesms, init_plugin, info);

#endif
