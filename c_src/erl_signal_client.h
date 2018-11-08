#pragma once

#include <stdint.h>


#include "libsignal-c/signal_protocol.h"
#include "erl_signal_client_storage.h"

typedef struct esc_mutexes {
  #ifndef NO_THREADS
  pthread_mutex_t * mutex_p;
  pthread_mutexattr_t * mutex_attr_p;
  #endif
} esc_mutexes;

typedef signal_buffer esc_buf;
typedef signal_protocol_address esc_address;

struct esc_context {
    signal_context * global_context_p = NULL;
    signal_protocol_store_context * store_context_p = NULL;
    esc_mutexes * mutexes_p = NULL;
    esc_storage * session_store = NULL;
    esc_storage * pre_key_store = NULL;
    esc_storage * signed_pre_key_store = NULL;
    esc_storage * identity_key_store = NULL;
    esc_storage * settings = NULL;
    void (*log_func)(int level, const char * message, size_t len, void * user_data);
    int log_level;
};

struct esc_handshake {
  session_builder * session_builder_p = NULL;
  esc_buf * handshake_msg_p = NULL;
};

struct esc_buf_list_item {
  uint32_t id;
  esc_buf * buf_p = NULL;
  esc_buf_list_item * next_p = NULL;
};

struct esc_bundle {
  uint32_t registration_id;
  esc_buf_list_item * pre_keys_head_p = NULL;
  uint32_t signed_pre_key_id;
  esc_buf * signed_pre_key_public_serialized_p = NULL;
  esc_buf * signed_pre_key_signature_p = NULL;
  esc_buf * identity_key_public_serialized_p = NULL;
};

#define ESC_LOG_ERROR   0
#define ESC_LOG_WARNING 1
#define ESC_LOG_NOTICE  2
#define ESC_LOG_INFO    3
#define ESC_LOG_DEBUG   4

#define ESC_ERR                  -10000
#define ESC_ERR_NOMEM            -10001
#define ESC_ERR_NOT_A_PREKEY_MSG -10100
#define ESC_ERR_INVALID_KEY_ID   -10200

#define ESC_DB_DEFAULT_FN "axc.sqlite"
#define ESC_PRE_KEYS_AMOUNT 100

/**
 * Allocates the axc context.
 *
 * @param ctx_pp Will point to the created context.
 * @return 0 on success, negative on failure
 */
int esc_context_create(esc_context ** ctx_pp);

/**
 * Sets the filename/location of the db.
 * Should be done after creating the context, but before calling esc_init().
 *
 * @param ctx_p The fresh axc context.
 * @param filename The filename/path to be used.
 * @param fn_len Length of the filename.
 * @return 0 on success, negative on failure
 */
int esc_context_set_db_fn(esc_context * ctx_p, char * filename, size_t fn_len);

/**
 * Returns the filename to be used for the database.
 *
 * @param ctx_p The axc context.
 * @return The filename set via esc_context_set_db_fn(), or ESC_DEFAULT_DB_FN if none was set.
 */
const char * esc_context_get_db_fn(esc_context * ctx_p);

void esc_context_set_log_func(esc_context * ctx_p, void (*log_func)(int level, const char * message, size_t len, void * user_data));
void esc_context_set_log_level(esc_context * ctx_p, int level);
int esc_context_get_log_level(esc_context * ctx_p);

void esc_context_destroy_all(esc_context * ctx_p);
signal_context * esc_context_get_axolotl_ctx(esc_context * ctx_p);

void esc_default_log(int level, const char *message, size_t len, void *user_data);
void esc_log(esc_context * ctx_p, int level, const char * format, ...);

int esc_buf_list_item_create(esc_buf_list_item ** item_pp, uint32_t * id_p, esc_buf * data_p);
void esc_buf_list_item_set_next(esc_buf_list_item * item_p, esc_buf_list_item * next_p);
esc_buf_list_item * esc_buf_list_item_get_next(esc_buf_list_item * item_p);
uint32_t esc_buf_list_item_get_id(esc_buf_list_item * item_p);
esc_buf * esc_buf_list_item_get_buf(esc_buf_list_item * item_p);
void esc_buf_list_free(esc_buf_list_item * head_p);

/**
 * Collects the info needed to publish a bundle.
 *
 * @param n Number of pre keys to get.
 * @param ctx_p Pointer to the initialized axc context.
 * @param bundle_pp Will be set to the bundle.
 * @return 0 on success, negative on error.
 */
int esc_bundle_collect(size_t n, esc_context * ctx_p, esc_bundle ** bundle_pp);
uint32_t esc_bundle_get_reg_id(esc_bundle * bundle_p);
esc_buf_list_item * esc_bundle_get_pre_key_list(esc_bundle * bundle_p);
uint32_t esc_bundle_get_signed_pre_key_id(esc_bundle * bundle_p);
esc_buf * esc_bundle_get_signed_pre_key(esc_bundle * bundle_p);
esc_buf * esc_bundle_get_signature(esc_bundle * bundle_p);
esc_buf * esc_bundle_get_identity_key(esc_bundle * bundle_p);
void esc_bundle_destroy(esc_bundle * bundle_p);

/**
 * Initializes the library. Has to be called at every startup.
 *
 * @param ctx_p A pointer to an already created axc context.
 * @return 0 on success, negative on failure
 */
int esc_init(esc_context * ctx_p);

/**
 * Generates identity keys and store them in internal storage
 * 
 * @param ctx_p A pointer to an already created axc context.
 * @return 0 on success, negative on failure
 */
const char * esc_generate_identity_keys(esc_context * ctx_p);

/**
 * Destroys mutexes and axolotl contexts saved in the axc context.
 *
 * @param ctx_p Pointer to the axc context as received from esc_init().
 */
void esc_cleanup(esc_context * ctx_p);

/**
 * "Installs" the library by creating the database and saving the necessary encryption keys into it.
 * Needs to be called once at the beginning, but can be called at every startup as it will not touch an initialized database.
 *
 * @param ctx_p Pointer to the axc context as received from esc_init().
 * @return 0 on success, negative on failure
 */
int esc_install(esc_context * ctx_p);

/**
 * Retrieves the local registration ID.
 *
 * @param ctx_p Pointer to an initialized and installed esc_context.
 * @param id_p Will be set to the ID.
 * @return 0 on success, negative on error.
 */
int esc_get_device_id(esc_context * ctx_p, uint32_t * id_p);

esc_buf * esc_buf_create(const uint8_t * data, size_t len);
uint8_t * esc_buf_get_data(esc_buf * buf);
size_t esc_buf_get_len(esc_buf * buf);
void esc_buf_free(esc_buf * buf);

esc_buf * esc_handshake_get_data(esc_handshake * handshake_p);

/**
 * Generates the message that is needed to initiate a session synchronously, which internally is axolotl's key_exchange_message.
 * The returned esc_handshake has to be kept and given to esc_handshake_acknowledge(), together with the received response.
 * At the end, it should be freed by calling esc_handshake_destroy().
 *
 * The whole key exchange process looks like this:
 * A initiate
 * A -> B
 * B accept
 * B -> A
 * A acknowledge
 *
 * @param recipient_addr_p The address of the recipient.
 * @param ctx_p The client context.
 * @param handshake_pp The handshake struct to keep for the next steps.
 * @return 0 on success, negative on error
 */
int esc_handshake_initiate(esc_address * recipient_addr_p, esc_context * ctx_p, esc_handshake ** handshake_init_pp);

/**
 * Second step of the session establishment, is called by the recipient.
 *
 * @param msg_data_p A pointer to a buffer with the raw message data.
 * @param sender_addr_p A pointer to an address struct with the sender's information.
 * @param ctx_p The axc context.
 * @param handshake_response_pp Will point to the response message if successful, unset otherwise. Has to be freed using esc_handshake_destroy().
 * @return 0 on success, negative on error.
 */
int esc_handshake_accept(esc_buf * msg_data_p, esc_address * sender_addr_p, esc_context * ctx_p, esc_handshake ** handshake_response_pp);

/**
 * Third and final step of session establishment.
 *
 * @param msg_data_p A pointer to a buffer containing the raw message data.
 * @param handshake_p Pointer to the esc_handshake returned by esc_handshake_initiate(). Should be freed by esc_handshake_destroy() afterwards.
 * @param ctx_p The axc context.
 * @return 0 on success, negative on error.
 *
 */
int esc_handshake_acknowledge(esc_buf * msg_data_p, esc_handshake * handshake_p, esc_context * ctx_p);

/**
 * Frees the memory used by this struct and its members.
 *
 * @param The esc_handshake to destroy.
 */
void esc_handshake_destroy(esc_handshake * hs);

/**
 * Encrypts a message. Needs an established session, either synchronous or built from bundle.
 * The buffer containing the ciphertext has to be freed afterwards.
 *
 * If data is a string, include the null terminator in the data.
 *
 * @param msg_p The data to encrypt.
 * @param recipient_addr_p Address of the recipient.
 * @param ctx_p The axc context.
 * @param ciphertext_pp Will point to the serialized ciphertext afterwards.
 * @return 0 on success, negative on error.
 */
int esc_message_encrypt_and_serialize(esc_buf * msg_p, const esc_address * recipient_addr_p, esc_context * ctx_p, esc_buf ** ciphertext_pp);

/**
 * Decrypts a received message. Needs an established session.
 *
 * As the null terminator should be included in the data bytes to be encrypted in case of a string,
 * the data of the esc_buf should also work as a string after decryption.
 *
 * @param msg_p The data to decrypt.
 * @param sender_addr_p Address of the sender.
 * @param ctx_p The axc context.
 * @param plaintext_pp Will point to the plaintext afterwards. Has to be freed.
 * @return 0 on success, negative on error.
 */
int esc_message_decrypt_from_serialized (esc_buf * msg_p, esc_address * sender_addr_p, esc_context * ctx_p, esc_buf ** plaintext_pp);

/**
 * Checks if an initiated session exists (and no pending synchronous handshake).
 *
 * @param addr_p The address for which to check if a session exists.
 * @param ctx_p The axc context.
 * @return 1 if it exists, 0 if it does not, negative on error
 */
int esc_session_exists_initiated(const esc_address * addr_p, esc_context * ctx_p);

/**
 * Checks if there exists a session for a user.
 *
 * @param name The username.
 * @param ctx_p Pointer to the axc context.
 * @return 1 if at least one session exists, 0 if no session exists, negative on error.
 */
int esc_session_exists_any(const char * name, esc_context * ctx_p);

/**
 * Creates a session from a fetched bundle which can then instantly be used to encrypt a message.
 *
 * @param pre_key_id The ID of the used prekey.
 * @param pre_key_public_serialized_p Pointer to a buffer containing the serialized public part of the pre key pair.
 * @param signed_pre_key_id The ID of the signed prekey.
 * @param signed_pre_key_public_serialized_p Pointer to a buffer containing the serialized public part of the signed pre key pair.
 * @param signed_pre_key_signature_p Pointer to a buffer containing the signature data of the signed pre key.
 * @param identity_key_public_serialized_p Pointer to a buffer containing the serialized public part of the identity key pair.
 * @param remote_address_p Pointer to the address of the recipient.
 * @param ctx_p Pointer to the esc_context.
 * @return 0 on success, negative on error.
 */
int esc_session_from_bundle(uint32_t pre_key_id,
                            esc_buf * pre_key_public_serialized_p,
                            uint32_t signed_pre_key_id,
                            esc_buf * signed_pre_key_public_serialized_p,
                            esc_buf * signed_pre_key_signature_p,
                            esc_buf * identity_key_public_serialized_p,
                            const esc_address * remote_address_p,
                            esc_context * ctx_p);

/**
 * Deletes a session for a user:device combination.
 *
 * @param user Username.
 * @param device_id The device ID.
 * @param ctx_p Pointer to the axc context.
 * @return 0 on success, negative on error.
 */
int esc_session_delete(const char * user, uint32_t device_id, esc_context * ctx_p);

/**
 * Creates a session from a received pre key message and uses it to decrypt the actual message body..
 * The ciphertext is decrypted here to avoid reserializing the message or having to deal with internal axolotl data structures.
 *
 * @param pre_key_msg_serialized_p Pointer to the buffer containing the serialized message.
 * @param remote_address_p Pointer to the remote (sender) address.
 * @param ctx_p Pointer to the axc context.
 * @param msg_pp Will contain a pointer to the decrypted plaintext.
 * @return 0 on success, negative on error
 */
int esc_pre_key_message_process(esc_buf * pre_key_msg_serialized_p, esc_address * remote_address_p, esc_context * ctx_p, esc_buf ** plaintext_pp);

/**
 * Retrieves the own public identity key.
 *
 * @param ctx_p Pointer to the esc_context.
 * @param pubkey_data_pp Will point to an esc_buf * containing the serialized key data.
 * @return 0 on success, negative on error.
 */
int esc_key_load_public_own(esc_context * ctx_p, esc_buf ** pubkey_data_pp);

/**
 * Retrieves the serialized public identity key for a user's device.
 *
 * @param name The user's name.
 * @param device_id The device's ID.
 * @param ctx_p Pointer to the esc_context.
 * @param pubkey_data_pp Will point to an esc_buf * which contains the data.
 * @return 1 if the key was loaded, 0 if no session exists, negative on error.
 */
int esc_key_load_public_addr(const char * name, uint32_t device_id, esc_context * ctx_p, esc_buf ** pubkey_data_pp);
