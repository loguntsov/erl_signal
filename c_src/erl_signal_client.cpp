#include <inttypes.h>
#include <stdarg.h> // va_*
#include <stdio.h> // printf, fprintf
#include <stdlib.h> // exit, malloc
#include <string.h> // memset

#ifndef NO_THREADS
#include <pthread.h> // mutex stuff
#endif

#include <glib.h>

#include "libsignal-c/signal_protocol.h"
#include "libsignal-c/key_helper.h"
#include "libsignal-c/protocol.h"
#include "libsignal-c/session_builder.h"
#include "libsignal-c/session_builder_internal.h"
#include "libsignal-c/session_cipher.h"
#include "libsignal-c/session_state.h"

#include "erl_signal_client.h"
#include "erl_signal_store.h"
#include "erl_signal_crypto.h"
#include "erl_signal_client_storage.h"

#include "erl_signal_log.h"

#include <ctime>

void recursive_mutex_lock(void * user_data);
void recursive_mutex_unlock(void * user_data);


void si_log(int level, const char *message, size_t len, void *user_data) {
  std::string c = std::string(message, len);
  std::cout << c << "\n";
}

int esc_buf_list_item_create(esc_buf_list_item ** item_pp, uint32_t * id_p, esc_buf * data_p) {
  esc_buf_list_item * item_p = new esc_buf_list_item();
  if (!item_p) {
    return -1;
  }
  memset(item_p, 0, sizeof(esc_buf_list_item));

  if (id_p) {
    item_p->id = *id_p;
  }
  if (data_p) {
    item_p->buf_p = data_p;
  }

  *item_pp = item_p;
  return 0;
}

void esc_buf_list_item_set_next(esc_buf_list_item * item_p, esc_buf_list_item * next_p) {
  item_p->next_p = next_p;
}

esc_buf_list_item * esc_buf_list_item_get_next(esc_buf_list_item * item_p) {
  return item_p->next_p;
}

uint32_t esc_buf_list_item_get_id(esc_buf_list_item * item_p) {
  return item_p->id;
}

esc_buf * esc_buf_list_item_get_buf(esc_buf_list_item * item_p) {
  return item_p->buf_p;
}

void esc_buf_list_free(esc_buf_list_item * head_p) {
  esc_buf_list_item * next = head_p;
  esc_buf_list_item * temp = NULL;

  while (next) {
    esc_buf_free(next->buf_p);
    temp = next->next_p;
    free(next);
    next = temp;
  }
}

int esc_bundle_collect(size_t n, esc_context * ctx_p, esc_bundle ** bundle_pp) {
  int ret_val = 0;
  const char * err_msg = "";

  esc_bundle * bundle_p = NULL;
  uint32_t reg_id = 0;
  esc_buf_list_item * pre_key_list_p = NULL;
  uint32_t signed_prekey_id = 0; //FIXME: right now, only one is ever generated, this should be changed
  session_signed_pre_key * signed_prekey_p = NULL;
  ec_key_pair * signed_prekey_pair_p = NULL;
  ec_public_key * signed_prekey_public_p = NULL;
  esc_buf * signed_prekey_public_data_p = NULL;
  esc_buf * signed_prekey_signature_data_p = NULL;
  ratchet_identity_key_pair * identity_key_pair_p = NULL;
  ec_public_key * identity_key_public_p = NULL;
  esc_buf * identity_key_public_data_p = NULL;

  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: entered", __func__);

  bundle_p = new esc_bundle();
  if (!bundle_p) {
    err_msg = "failed to malloc bundle";
    ret_val = ESC_ERR_NOMEM;
    goto cleanup;
  }
  memset(bundle_p, 0, sizeof(esc_bundle));

  ret_val = esc_get_device_id(ctx_p, &reg_id);
  if (ret_val) {
    err_msg = "failed to retrieve device id";
    goto cleanup;
  }
  bundle_p->registration_id = reg_id;

  ret_val = esc_db_pre_key_get_list(n, ctx_p, &pre_key_list_p);
  if (ret_val) {
    err_msg = "failed to retrieve pre key list";
    goto cleanup;
  }
  bundle_p->pre_keys_head_p = pre_key_list_p;

  ret_val = signal_protocol_signed_pre_key_load_key(ctx_p->store_context_p, &signed_prekey_p, signed_prekey_id);
  if (ret_val) {
    err_msg = "failed to get signed pre key";
    goto cleanup;
  }
  signed_prekey_pair_p = session_signed_pre_key_get_key_pair(signed_prekey_p);
  signed_prekey_public_p = ec_key_pair_get_public(signed_prekey_pair_p);

  ret_val = ec_public_key_serialize(&signed_prekey_public_data_p, signed_prekey_public_p);
  if (ret_val) {
    err_msg = "failed to serialize signed pre key";
    goto cleanup;
  }
  bundle_p->signed_pre_key_public_serialized_p = signed_prekey_public_data_p;

  signed_prekey_signature_data_p = esc_buf_create(session_signed_pre_key_get_signature(signed_prekey_p),
                                                  session_signed_pre_key_get_signature_len(signed_prekey_p));
  if (!signed_prekey_signature_data_p) {
    ret_val = ESC_ERR;
    err_msg = "failed to create buffer for signature data";
    goto cleanup;
  }
  bundle_p->signed_pre_key_signature_p = signed_prekey_signature_data_p;

  ret_val = signal_protocol_identity_get_key_pair(ctx_p->store_context_p, &identity_key_pair_p);
  if (ret_val) {
    err_msg = "failed to retrieve identity key pair";
    goto cleanup;
  }
  identity_key_public_p = ratchet_identity_key_pair_get_public(identity_key_pair_p);

  ret_val = ec_public_key_serialize(&identity_key_public_data_p, identity_key_public_p);
  if (ret_val) {
    err_msg = "failed to serialize identity key";
    goto cleanup;
  }
  bundle_p->identity_key_public_serialized_p = identity_key_public_data_p;

  *bundle_pp = bundle_p;

cleanup:
  if (ret_val) {
    esc_buf_list_free(pre_key_list_p);
    esc_buf_free(signed_prekey_public_data_p);
    esc_buf_free(signed_prekey_signature_data_p);
    esc_buf_free(identity_key_public_data_p);
    free(bundle_p);
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  SIGNAL_UNREF(signed_prekey_p);
  SIGNAL_UNREF(identity_key_pair_p);
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: leaving", __func__);
  return ret_val;
}

uint32_t esc_bundle_get_reg_id(esc_bundle * bundle_p) {
  return bundle_p->registration_id;
}

esc_buf_list_item * esc_bundle_get_pre_key_list(esc_bundle * bundle_p) {
  return bundle_p->pre_keys_head_p;
}

uint32_t esc_bundle_get_signed_pre_key_id(esc_bundle * bundle_p) {
  return bundle_p->signed_pre_key_id;
}

esc_buf * esc_bundle_get_signed_pre_key(esc_bundle * bundle_p) {
  return bundle_p->signed_pre_key_public_serialized_p;
}

esc_buf * esc_bundle_get_signature(esc_bundle * bundle_p) {
  return bundle_p->signed_pre_key_signature_p;
}

esc_buf * esc_bundle_get_identity_key(esc_bundle * bundle_p) {
  return bundle_p->identity_key_public_serialized_p;
}

void esc_bundle_destroy(esc_bundle * bundle_p) {
  if (bundle_p) {
    esc_buf_list_free(bundle_p->pre_keys_head_p);
    esc_buf_free(bundle_p->signed_pre_key_public_serialized_p);
    esc_buf_free(bundle_p->signed_pre_key_signature_p);
    esc_buf_free(bundle_p->identity_key_public_serialized_p);
  }
}

void esc_default_log(int level, const char *message, size_t len, void *user_data) {
  (void) len;

  esc_context * ctx_p = (esc_context *) user_data;

  if (ctx_p->log_level >= ESC_LOG_ERROR) {
    switch(level) {
    case ESC_LOG_ERROR:
      fprintf(stderr, "[AXC ERROR] %s\n", message);
      break;
    case ESC_LOG_WARNING:
      if (ctx_p->log_level >= ESC_LOG_WARNING) {
        fprintf(stderr, "[AXC WARNING] %s\n", message);
      }
      break;
    case ESC_LOG_NOTICE:
      if (ctx_p->log_level >= ESC_LOG_NOTICE) {
        fprintf(stderr, "[AXC NOTICE] %s\n", message);
      }
      break;
    case ESC_LOG_INFO:
      if (ctx_p->log_level >= ESC_LOG_INFO) {
        fprintf(stdout, "[AXC INFO] %s\n", message);
      }
      break;
    case ESC_LOG_DEBUG:
      if (ctx_p->log_level >= ESC_LOG_DEBUG) {
        fprintf(stdout, "[AXC DEBUG] %s\n", message);
      }
      break;
    default:
      if (ctx_p->log_level > ESC_LOG_DEBUG) {
        fprintf(stderr, "[AXC %d] %s\n", level, message);
      }
      break;
    }
  }
}

void esc_log(esc_context * ctx_p, int level, const char * format, ...) {
/*
  if(ctx_p->log_func) {
    va_list args;
    va_list args_cpy;
    va_copy(args_cpy, args);

    va_start(args, format);
    size_t len = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);

    char msg[len];
    va_start(args_cpy, format);
    size_t final_len = vsnprintf(msg, len, format, args_cpy);
    va_end(args_cpy);
    if(final_len > 0) {
      ctx_p->log_func(level, msg, len, ctx_p);
    }
  }
*/
}

int esc_mutexes_create_and_init(esc_mutexes ** mutexes_pp) {
  #ifndef NO_THREADS
  esc_mutexes * mutexes_p = new esc_mutexes();
  if (!mutexes_p) {
    return -1;
  }
  memset(mutexes_p, 0, sizeof(esc_mutexes));
  *mutexes_pp = mutexes_p;

  pthread_mutex_t * mutex_p = new pthread_mutex_t();
  if (!mutex_p) {
    return -2;
  }
  mutexes_p->mutex_p = mutex_p;

  pthread_mutexattr_t * mutex_attr_p = new pthread_mutexattr_t();
  if (!mutex_attr_p) {
    return -3;
  }
  mutexes_p->mutex_attr_p = mutex_attr_p;

  if (pthread_mutexattr_init(mutex_attr_p)) {
    return -4;
  }
  if (pthread_mutexattr_settype(mutex_attr_p, PTHREAD_MUTEX_RECURSIVE)) {
    return -5;
  }

  if (pthread_mutex_init(mutex_p, mutex_attr_p)) {
    return -6;
  }
  #else
  *mutexes_pp = NULL;
  #endif


  return 0;
}

void esc_mutexes_destroy(esc_mutexes * mutexes_p) {
  #ifndef NO_THREADS
  if (mutexes_p) {
    if (mutexes_p->mutex_p) {
      pthread_mutex_destroy(mutexes_p->mutex_p);
      free(mutexes_p->mutex_p);
    }

    if (mutexes_p->mutex_attr_p) {
      pthread_mutexattr_destroy(mutexes_p->mutex_attr_p);
      free(mutexes_p->mutex_attr_p);
    }

    free(mutexes_p);
  }
  #else
  (void) mutexes_p;
  #endif
}

int esc_context_create(esc_context ** ctx_pp) {
  if (!ctx_pp) {
    return -1;
  }

  esc_context * ctx_p = NULL;
  ctx_p = new esc_context();
  if (!ctx_p) {
    return -2;
  }
  memset(ctx_p, 0, sizeof(esc_context));

  ctx_p->log_level = -1;

  ctx_p->pre_key_store = new esc_storage();
  ctx_p->session_store = new esc_storage();
  ctx_p->signed_pre_key_store = new esc_storage();
  ctx_p->identity_key_store = new esc_storage();  
  ctx_p->settings = new esc_storage();

  *ctx_pp = ctx_p;
  return 0;
}

const char * esc_context_get_db_fn(esc_context * ctx_p) {
/**
  if (ctx_p->db_filename) {
    return ctx_p->db_filename;
  } else {
    return ESC_DB_DEFAULT_FN;
  }
**/  
  return ESC_DB_DEFAULT_FN;  
}

void esc_context_set_log_func(esc_context * ctx_p, void (*log_func)(int level, const char * message, size_t len, void * user_data)) {
  ctx_p->log_func = log_func;
}

void esc_context_set_log_level(esc_context * ctx_p, int level) {
  ctx_p->log_level = level;
}

int esc_context_get_log_level(esc_context * ctx_p) {
  return ctx_p->log_level;
}

signal_context * esc_context_get_axolotl_ctx(esc_context * ctx_p) {
  return ctx_p != NULL ? ctx_p->global_context_p : NULL;
}

void esc_context_destroy_all(esc_context * ctx_p) {
  if (ctx_p) {
    delete ctx_p->pre_key_store;
    delete ctx_p->session_store;
    delete ctx_p->signed_pre_key_store;
    delete ctx_p->identity_key_store;
    delete ctx_p->settings;

    signal_context_destroy(ctx_p->global_context_p);
    signal_protocol_store_context_destroy(ctx_p->store_context_p);
    esc_mutexes_destroy(ctx_p->mutexes_p);
  }  
}

void recursive_mutex_lock(void * user_data) {
  #ifndef NO_THREADS
  esc_context * ctx_p = (esc_context *) user_data;
  pthread_mutex_lock(ctx_p->mutexes_p->mutex_p);
  #else
  (void) user_data;
  #endif
}

void recursive_mutex_unlock(void * user_data) {
  #ifndef NO_THREADS
  esc_context * ctx_p = (esc_context *) user_data;
  pthread_mutex_unlock(ctx_p->mutexes_p->mutex_p);
  #else
  (void) user_data;
  #endif
}

esc_buf * esc_buf_create(const uint8_t * data, size_t len) {
  return signal_buffer_create(data, len);
}

unsigned char * esc_buf_get_data(esc_buf * buf) {
  return (unsigned char * ) signal_buffer_data(buf);
}

size_t esc_buf_get_len(esc_buf * buf) {
  return signal_buffer_len(buf);
}

void esc_buf_free(esc_buf * buf) {
  signal_buffer_bzero_free(buf);
}

int esc_init(esc_context * ctx_p) {
  esc_context_set_log_func(ctx_p, &si_log);
  esc_log(ctx_p, ESC_LOG_INFO, "%s: initializing axolotl client", __func__);
  const char * err_msg = " ";
  int ret_val = 0;

  esc_mutexes * mutexes_p = NULL;
  signal_protocol_store_context * store_context_p = NULL;

  signal_protocol_session_store session_store = {
      .load_session_func = &esc_db_session_load,
      .get_sub_device_sessions_func = &esc_db_session_get_sub_device_sessions,
      .store_session_func = &esc_db_session_store,
      .contains_session_func = &esc_db_session_contains,
      .delete_session_func = &esc_db_session_delete,
      .delete_all_sessions_func = &esc_db_session_delete_all,
      .destroy_func = &esc_db_session_destroy_store_ctx,
      .user_data = ctx_p
  };
  signal_protocol_pre_key_store pre_key_store = {
      .load_pre_key = &esc_db_pre_key_load,
      .store_pre_key = &esc_db_pre_key_store,
      .contains_pre_key = &esc_db_pre_key_contains,
      .remove_pre_key = &esc_db_pre_key_remove,
      .destroy_func = &esc_db_pre_key_destroy_ctx,
      .user_data = ctx_p
  };
  signal_protocol_signed_pre_key_store signed_pre_key_store = {
      .load_signed_pre_key = &esc_db_signed_pre_key_load,
      .store_signed_pre_key = &esc_db_signed_pre_key_store,
      .contains_signed_pre_key = &esc_db_signed_pre_key_contains,
      .remove_signed_pre_key = &esc_db_signed_pre_key_remove,
      .destroy_func = &esc_db_signed_pre_key_destroy_ctx,
      .user_data = ctx_p
  };
  signal_protocol_identity_key_store identity_key_store = {
      .get_identity_key_pair = &esc_db_identity_get_key_pair,
      .get_local_registration_id = &esc_db_identity_get_local_registration_id,
      .save_identity = &esc_db_identity_save,
      .is_trusted_identity = &esc_db_identity_always_trusted,
      .destroy_func = &esc_db_identity_destroy_ctx,
      .user_data = ctx_p
  };

  // 2. init and set crypto provider
  signal_crypto_provider crypto_provider = {
      .random_func = random_bytes,
      .hmac_sha256_init_func = hmac_sha256_init,
      .hmac_sha256_update_func = hmac_sha256_update,
      .hmac_sha256_final_func = hmac_sha256_final,
      .hmac_sha256_cleanup_func = hmac_sha256_cleanup,
      .sha512_digest_init_func = sha512_digest_init,
      .sha512_digest_update_func = sha512_digest_update,
      .sha512_digest_final_func = sha512_digest_final,
      .sha512_digest_cleanup_func = sha512_digest_cleanup,
      .encrypt_func = aes_encrypt,
      .decrypt_func = aes_decrypt,
      .user_data = ctx_p
  };

  // init mutexes
  ret_val = esc_mutexes_create_and_init(&mutexes_p);
  if (ret_val) {
    err_msg = "failed to create or init mutexes";
    goto cleanup;
  }
  ctx_p->mutexes_p = mutexes_p;

  // axolotl lib init
  // 1. create global context
  if (signal_context_create(&(ctx_p->global_context_p), ctx_p)) {
    err_msg = "failed to create global axolotl context";
    ret_val = -1;
    goto cleanup;
  }

  signal_context_set_log_function(ctx_p->global_context_p, &si_log);
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: created and set axolotl context", __func__);

  if (signal_context_set_crypto_provider(ctx_p->global_context_p, &crypto_provider)) {
    err_msg = "failed to set crypto provider";
    ret_val = -1;
    goto cleanup;
  }
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: set axolotl crypto provider", __func__);

  // 3. set locking functions
  #ifndef NO_THREADS
  if (signal_context_set_locking_functions(ctx_p->global_context_p, recursive_mutex_lock, recursive_mutex_unlock)) {
    err_msg = "failed to set locking functions";
    ret_val = -1;
    goto cleanup;
  }
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: set locking functions", __func__);
  #endif

  // init store context

  if (signal_protocol_store_context_create(&store_context_p, ctx_p->global_context_p)) {
    err_msg = "failed to create store context";
    ret_val = -1;
    goto cleanup;
  }

  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: created store context", __func__);

  if (signal_protocol_store_context_set_session_store(store_context_p, &session_store)) {
    err_msg = "failed to create session store";
    ret_val = -1;
    goto cleanup;
  }

  if (signal_protocol_store_context_set_pre_key_store(store_context_p, &pre_key_store)) {
    err_msg = "failed to set pre key store";
    ret_val = -1;
    goto cleanup;
  }

  if (signal_protocol_store_context_set_signed_pre_key_store(store_context_p, &signed_pre_key_store)) {
    err_msg = "failed to set signed pre key store";
    ret_val = -1;
    goto cleanup;
  }

  if (signal_protocol_store_context_set_identity_key_store(store_context_p, &identity_key_store)) {
    err_msg = "failed to set identity key store";
    ret_val = -1;
    goto cleanup;
  }

  ctx_p->store_context_p = store_context_p;
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: set store context", __func__);

cleanup:
  if (ret_val < 0) {
    //FIXME: this frees inited context, make this more fine-grained
    esc_cleanup(ctx_p);
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
  } else {
    esc_log(ctx_p, ESC_LOG_INFO, "%s: done initializing axc", __func__);
  }
  return ret_val;
}

void esc_cleanup(esc_context * ctx_p) {
  esc_context_destroy_all(ctx_p);
}

int esc_install(esc_context * ctx_p) {
  return -1;
}
/**
  const char * err_msg = "";
  int ret_val = 0;
  int db_needs_init = 0;

  ratchet_identity_key_pair * identity_key_pair_p = NULL;
  signal_protocol_key_helper_pre_key_list_node * pre_keys_head_p = NULL;
  session_pre_key * last_resort_key_p = NULL;
  session_signed_pre_key * signed_pre_key_p = NULL;
  signal_buffer * last_resort_key_buf_p = NULL;
  signal_buffer * signed_pre_key_data_p = NULL;

  esc_log(ctx_p, ESC_LOG_INFO, "%s: calling install-time functions", __func__);

  int init_status = 0;
  int db_needs_reset = 0;
/*
  ret_val = esc_db_create(ctx_p);
  if (ret_val){
    err_msg = "failed to create db";
    goto cleanup;
  }
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: created db if it did not exist already", __func__);


  init_status = ESC_DB_NOT_INITIALIZED;
  ret_val = esc_db_init_status_get(&init_status, ctx_p);
  switch (ret_val) {
    case -1:
    default:
      err_msg = "failed to read init status";
      goto cleanup;
      break;
    case 0:
      // there is a value
      switch (init_status) {
        case ESC_DB_NOT_INITIALIZED:
          // init needed
          db_needs_init = 1;
          break;
        case ESC_DB_NEEDS_ROLLBACK:
          // reset and init needed
          db_needs_reset = 1;
          db_needs_init = 1;
          break;
        case ESC_DB_INITIALIZED:
        default:
          // the db is already initialised
          break;
      }
      break;
    case 1:
      // no value = not initialised -> init needed
      db_needs_init = 1;
      break;
  }

  if (db_needs_reset) {
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: db needs reset", __func__ );
    ret_val = esc_db_destroy(ctx_p);
    if (ret_val) {
      err_msg = "failed to reset db";
      goto cleanup;
    }

    ret_val = esc_db_create(ctx_p);
    if (ret_val) {
      err_msg = "failed to create db after reset";
      goto cleanup;
    }
  } else {
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: db does not need reset", __func__ );
  }


cleanup:
  if (ret_val < 0) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  if (db_needs_init) {
    SIGNAL_UNREF(identity_key_pair_p);
    signal_protocol_key_helper_key_list_free(pre_keys_head_p);
    SIGNAL_UNREF(last_resort_key_p);
    SIGNAL_UNREF(signed_pre_key_p);
    signal_buffer_bzero_free(last_resort_key_buf_p);
    signal_buffer_bzero_free(signed_pre_key_data_p);
  }

  return ret_val;
} */

const char * esc_generate_identity_keys(esc_context * ctx_p) {
  const char * err_msg = NULL;
  int ret_val = 0;

  ratchet_identity_key_pair *identity_key_pair;
  uint32_t registration_id;
  signal_protocol_key_helper_pre_key_list_node *pre_keys_head;
  session_signed_pre_key *signed_pre_key;
  ec_public_key *p;

  ret_val = signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair, ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to generate the identity key pair";
    goto cleanup;    
  }  
  
  ret_val = signal_protocol_key_helper_generate_registration_id(&registration_id, 0, ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to generate registration id";
    goto cleanup;
  }
  
  ret_val = signal_protocol_key_helper_generate_pre_keys(&pre_keys_head, 0, ESC_PRE_KEYS_AMOUNT, ctx_p->global_context_p);
  if(ret_val) {
    err_msg = "failed to generate pre keys";
    goto cleanup;
  }

  ret_val = signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, identity_key_pair, 5, ( uint64_t ) std::time(NULL), ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to generate signed pre key";
    goto cleanup;
  }

  ret_val = esc_db_identity_set_key_pair(identity_key_pair, ctx_p);
  if (ret_val) {
    err_msg = "failed to set identity key pair";
    goto cleanup;
  }
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: saved identity key pair", __func__ );

  ret_val = esc_db_identity_set_local_registration_id(registration_id, ctx_p);
  if (ret_val) {
    err_msg = "failed to set registration id";
    goto cleanup;
  }
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: saved registration id", __func__ );

  ret_val = esc_db_pre_key_store_list(pre_keys_head, ctx_p);
  if (ret_val) {
    err_msg = "failed to save pre key list";
    goto cleanup;
  }
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: saved pre keys", __func__ );

cleanup:
  if ( err_msg != NULL ) {
    es_log(err_msg);
    //esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  SIGNAL_UNREF(identity_key_pair);
  signal_protocol_key_helper_key_list_free(pre_keys_head);
  SIGNAL_UNREF(signed_pre_key);

  return err_msg;  
}

int esc_get_device_id(esc_context * ctx_p, uint32_t * id_p) {
  return signal_protocol_identity_get_local_registration_id(ctx_p->store_context_p, id_p);
}

const char * esc_message_encrypt_and_serialize(esc_buf * msg_p, const esc_address * recipient_addr_p, esc_context * ctx_p, esc_buf ** ciphertext_pp) {
  const char * err_msg = NULL;
  int ret_val = 0;

  session_cipher * cipher_p = NULL;
  ciphertext_message * cipher_msg_p = NULL;
  signal_buffer * cipher_msg_data_p = NULL;
  esc_buf * cipher_msg_data_cpy_p = NULL;

  if (!ctx_p) {
    return "context_is_null";
  }

  if (!msg_p) {
    err_msg = "could not encrypt because msg pointer is null";
    goto cleanup;
  }
  if (!recipient_addr_p) {
    err_msg = "could not encrypt because recipient addr pointer is null";
    goto cleanup;
  }
  if (!ciphertext_pp) {
    err_msg = "could not encrypt because ciphertext pointer is null";
    goto cleanup;
  }


  ret_val = session_cipher_create(&cipher_p, ctx_p->store_context_p, recipient_addr_p, ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to create session cipher";
    goto cleanup;
  }

  es_log_hex("message: ", (char *) esc_buf_get_data(msg_p), esc_buf_get_len(msg_p));

  ret_val = session_cipher_encrypt(cipher_p, esc_buf_get_data(msg_p), esc_buf_get_len(msg_p), &cipher_msg_p);

  if (ret_val) {
    // err_msg = (new std::string(std::to_string(ret_val)))->c_str(); 
    err_msg = "failed to encrypt the message";
    goto cleanup;
  }

  cipher_msg_data_p = ciphertext_message_get_serialized(cipher_msg_p);
  cipher_msg_data_cpy_p = signal_buffer_copy(cipher_msg_data_p);

  if (!cipher_msg_data_cpy_p) {
    err_msg = "failed to copy cipher msg data";
    goto cleanup;
  }

  es_log_hex("encoded message: ", (char *) esc_buf_get_data(cipher_msg_data_cpy_p), esc_buf_get_len(cipher_msg_data_cpy_p));

  *ciphertext_pp = cipher_msg_data_cpy_p;

cleanup:
  if (err_msg != NULL) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
    esc_buf_free(cipher_msg_data_cpy_p);
  }

  session_cipher_free(cipher_p);
  SIGNAL_UNREF(cipher_msg_p);

  return err_msg;

}

const char * esc_message_decrypt_from_serialized (esc_buf * msg_p, esc_address * sender_addr_p, esc_context * ctx_p, esc_buf ** plaintext_pp) {
  const char * err_msg = NULL;
  int ret_val = 0;

  //TODO: add session_cipher_set_decryption_callback maybe?
  //FIXME: check message type

  pre_key_signal_message * ciphertext_p = NULL;
  signal_message * shortciphertext_p = NULL;
  session_cipher * cipher_p = NULL;
  esc_buf * plaintext_buf_p = NULL;

  if (!ctx_p) {
    fprintf(stderr, "%s: axc ctx is null!\n", __func__);
    return "context_is_null";
  }

  if (!msg_p) {
    err_msg = "could not decrypt because message pointer is null";
    ret_val = -1;
    goto cleanup;
  }
  if (!sender_addr_p) {
    err_msg = "could not decrypt because sender address pointer is null";
    ret_val = -1;
    goto cleanup;
  }
  if (!plaintext_pp) {
    err_msg = "could not decrypt because plaintext pointer is null";
    ret_val = -1;
    goto cleanup;
  }

  es_log_hex("sender`: ", (char *) sender_addr_p->name, sender_addr_p->name_len);

  ret_val = session_cipher_create(&cipher_p, ctx_p->store_context_p, sender_addr_p, ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to create session cipher";
    goto cleanup;
  }

  es_log_hex("des: ", (char *) esc_buf_get_data(msg_p), esc_buf_get_len(msg_p));

  ret_val = pre_key_signal_message_deserialize(&ciphertext_p, esc_buf_get_data(msg_p), esc_buf_get_len(msg_p), ctx_p->global_context_p);
  if (ret_val == 0 ) {
    ret_val = session_cipher_decrypt_pre_key_signal_message(cipher_p, ciphertext_p, NULL, &plaintext_buf_p);
    if (ret_val != 0) {
      //err_msg = (new std::string(std::to_string(ret_val)))->c_str();     
      err_msg = "cant_decrypt_signal_message";
      goto cleanup;
    }
  } else {
    ret_val = signal_message_deserialize(&shortciphertext_p, esc_buf_get_data(msg_p), esc_buf_get_len(msg_p), ctx_p->global_context_p);
    if (ret_val == 0 ) {
      ret_val = session_cipher_decrypt_signal_message(cipher_p, shortciphertext_p, NULL, &plaintext_buf_p);
      if (ret_val!=0) {
        err_msg = "cant_decrypt_signal_message";
        goto cleanup;
      }
    } else {
      err_msg = "uknown_type_of_message";
      goto cleanup;      
    }
  }    

  *plaintext_pp = signal_buffer_copy(plaintext_buf_p);  

cleanup:
  if (err_msg!=NULL) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  session_cipher_free(cipher_p);
  SIGNAL_UNREF(ciphertext_p);
  SIGNAL_UNREF(shortciphertext_p);

  return err_msg;
}

int esc_session_exists_initiated(const esc_address * addr_p, esc_context * ctx_p) {
  int ret_val = 0;
  const char * err_msg = "";

  session_record * session_record_p = NULL;
  session_state * session_state_p = NULL;

  //TODO: if there was no response yet, even though it is an established session it keeps sending prekeymsgs
  //      maybe that is "uninitiated" too?

  if(!signal_protocol_session_contains_session(ctx_p->store_context_p, addr_p)) {
    return 0;
  }

  ret_val = signal_protocol_session_load_session(ctx_p->store_context_p, &session_record_p, addr_p);
  if (ret_val){
    err_msg = "database error when trying to retrieve session";
    goto cleanup;
  } else {
    session_state_p = session_record_get_state(session_record_p);
    if (session_state_has_pending_key_exchange(session_state_p)) {
      err_msg = "session exists but has pending synchronous key exchange";
      ret_val = 0;
      goto cleanup;
    }

    ret_val = 1;
  }

cleanup:
  if (ret_val < 1) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  SIGNAL_UNREF(session_record_p);
  return ret_val;
}

/**
 * Checks if there exists a session for a user.
 *
 * @param name The username.
 * @param ctx_p Pointer to the axc context.
 * @return 0 if no session exists, 1 if at least one session exists, negative on error.
 */
int esc_session_exists_any(const char * name, esc_context * ctx_p) {
  int ret_val = 0;

  signal_int_list * sess_l_p = NULL;

  ret_val = signal_protocol_session_get_sub_device_sessions(ctx_p->store_context_p, &sess_l_p, name, strlen(name));
  if (ret_val < 0) {
    goto cleanup;
  }

  ret_val = (signal_int_list_size(sess_l_p) > 0) ? 1 : 0;

cleanup:
  signal_int_list_free(sess_l_p);
  return ret_val;
}



int esc_session_from_bundle(uint32_t pre_key_id,
                            esc_buf * pre_key_public_serialized_p,
                            uint32_t signed_pre_key_id,
                            esc_buf * signed_pre_key_public_serialized_p,
                            esc_buf * signed_pre_key_signature_p,
                            esc_buf * identity_key_public_serialized_p,
                            const esc_address * remote_address_p,
                            esc_context * ctx_p) {

  const char * err_msg = "";
  int ret_val = 0;

  ec_public_key * pre_key_public_p = NULL;
  ec_public_key * signed_pre_key_public_p = NULL;
  ec_public_key * identity_key_public_p = NULL;
  session_pre_key_bundle * bundle_p = NULL;
  session_builder * session_builder_p = NULL;

  ret_val = curve_decode_point(&pre_key_public_p,
                               esc_buf_get_data(pre_key_public_serialized_p),
                               esc_buf_get_len(pre_key_public_serialized_p),
                               ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to deserialize public pre key";
    goto cleanup;
  }


  ret_val = curve_decode_point(&signed_pre_key_public_p,
                               esc_buf_get_data(signed_pre_key_public_serialized_p),
                               esc_buf_get_len(signed_pre_key_public_serialized_p),
                               ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to deserialize signed public pre key";
    goto cleanup;
  }

  ret_val = curve_decode_point(&identity_key_public_p,
                               esc_buf_get_data(identity_key_public_serialized_p),
                               esc_buf_get_len(identity_key_public_serialized_p),
                               ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to deserialize public identity key";
    goto cleanup;
  }

  ret_val = session_pre_key_bundle_create(&bundle_p,
                                          remote_address_p->device_id,
                                          remote_address_p->device_id, // this value is ignored
                                          pre_key_id,
                                          pre_key_public_p,
                                          signed_pre_key_id,
                                          signed_pre_key_public_p,
                                          esc_buf_get_data(signed_pre_key_signature_p),
                                          esc_buf_get_len(signed_pre_key_signature_p),
                                          identity_key_public_p);
  if (ret_val) {
    err_msg = "failed to assemble bundle";
    goto cleanup;
  }

  ret_val = session_builder_create(&session_builder_p, ctx_p->store_context_p, remote_address_p, ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to create session builder";
    goto cleanup;
  }

  ret_val = session_builder_process_pre_key_bundle(session_builder_p, bundle_p);
  if (ret_val) {
    err_msg = "failed to process pre key bundle";
    goto cleanup;
  }

cleanup:
  if (ret_val) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  SIGNAL_UNREF(pre_key_public_p);
  SIGNAL_UNREF(signed_pre_key_public_p);
  SIGNAL_UNREF(identity_key_public_p);
  SIGNAL_UNREF(bundle_p);
  session_builder_free(session_builder_p);

  return ret_val;
}

int esc_session_delete(const char * user, int32_t device_id, esc_context * ctx_p) {
  int ret_val = 0;

  esc_address addr = {
    .name = user, 
    .name_len = strlen(user), 
    .device_id = device_id
  };
  ret_val = signal_protocol_session_delete_session(ctx_p->store_context_p, &addr);
  if (ret_val) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: failed to delete session for %s:%i", __func__, user, device_id);
  }

  return ret_val;
}

/*
int esc_pre_key_message_process(esc_buf * pre_key_msg_serialized_p, esc_address * remote_address_p, esc_context * ctx_p, esc_buf ** plaintext_pp) {
  const char * err_msg = "";
  int ret_val = 0;

  session_builder * session_builder_p = NULL;
  session_record * session_record_p = NULL;
  pre_key_signal_message * pre_key_msg_p = NULL;
  uint32_t new_id = 0;
  uint32_t pre_key_id = 0;
  session_cipher * session_cipher_p = NULL;
  esc_buf * plaintext_p = NULL;
  signal_protocol_key_helper_pre_key_list_node * key_l_p = NULL;


  ret_val = session_builder_create(&session_builder_p, ctx_p->store_context_p, remote_address_p, ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to create session builder";
    goto cleanup;
  }


  ret_val = signal_protocol_session_load_session(ctx_p->store_context_p, &session_record_p, remote_address_p);
  if (ret_val) {
    err_msg = "failed to load or create session record";
    goto cleanup;
  }


  ret_val = pre_key_signal_message_deserialize(&pre_key_msg_p,
                                                esc_buf_get_data(pre_key_msg_serialized_p),
                                                esc_buf_get_len(pre_key_msg_serialized_p),
                                                ctx_p->global_context_p);
  if (ret_val == SG_ERR_INVALID_PROTO_BUF) {
    err_msg = "not a pre key msg";
    ret_val = ESC_ERR_NOT_A_PREKEY_MSG;
    goto cleanup;
  } else if (ret_val == SG_ERR_INVALID_KEY_ID) {
    ret_val = ESC_ERR_INVALID_KEY_ID;
    goto cleanup;
  } else if (ret_val) {
    err_msg = "failed to deserialize pre key message";
    goto cleanup;
  }

  ret_val = esc_db_pre_key_get_max_id(ctx_p, &new_id);
  if (ret_val) {
    err_msg = "failed to retrieve max pre key id";
    goto cleanup;
  }


  do {
    ret_val = signal_protocol_key_helper_generate_pre_keys(&key_l_p, new_id, 1, ctx_p->global_context_p);
    if (ret_val) {
      err_msg = "failed to generate a new key";
      goto cleanup;
    }

    new_id++;

  } while (signal_protocol_pre_key_contains_key(ctx_p->store_context_p, session_pre_key_get_id(signal_protocol_key_helper_key_list_element(key_l_p))));



  ret_val = session_builder_process_pre_key_signal_message(session_builder_p, session_record_p, pre_key_msg_p, &pre_key_id);
  if (ret_val < 0) {
    err_msg = "failed to process pre key message";
    goto cleanup;
  }


  ret_val = session_cipher_create(&session_cipher_p, ctx_p->store_context_p, remote_address_p, ctx_p->global_context_p);
  if (ret_val) {
    err_msg = "failed to create session cipher";
    goto cleanup;
  }

  //FIXME: find a way to retain the key (for MAM catchup)
  ret_val = session_cipher_decrypt_pre_key_signal_message(session_cipher_p, pre_key_msg_p, NULL, &plaintext_p);
  if (ret_val) {
    err_msg = "failed to decrypt message";
    goto cleanup;
  }

  ret_val = signal_protocol_pre_key_store_key(ctx_p->store_context_p, signal_protocol_key_helper_key_list_element(key_l_p));
  if (ret_val) {
    err_msg = "failed to store new key";
    goto cleanup;
  }

  *plaintext_pp = plaintext_p;

cleanup:
  if (ret_val < 0) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  SIGNAL_UNREF(pre_key_msg_p);
  SIGNAL_UNREF(session_record_p);
  SIGNAL_UNREF(session_cipher_p);
  session_builder_free(session_builder_p);
  signal_protocol_key_helper_key_list_free(key_l_p);

  return ret_val;
}


/*
int esc_key_load_public_own(esc_context * ctx_p, esc_buf ** pubkey_data_pp) {
  const char * err_msg;
  int ret_val = 0;

  ratchet_identity_key_pair * kp_p = NULL;
  esc_buf * key_data_p = NULL;

  ret_val = signal_protocol_identity_get_key_pair(ctx_p->store_context_p, &kp_p);
  if (ret_val) {
    err_msg = "failed to load identity key pair";
    goto cleanup;
  }

  ret_val = ec_public_key_serialize(&key_data_p, ratchet_identity_key_pair_get_public(kp_p));
  if (ret_val) {
    err_msg = "failed to serialize public identity key";
    goto cleanup;
  }

  *pubkey_data_pp = key_data_p;

cleanup:
  if (ret_val) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
    esc_buf_free(key_data_p);
  }

  SIGNAL_UNREF(kp_p);

  return ret_val;
}

*/

/*
int esc_key_load_public_addr(const char * name, int32_t device_id, esc_context * ctx_p, esc_buf ** pubkey_data_pp) {
  const char * err_msg;
  int ret_val = 0;

  session_record * sr_p = NULL;
  ec_public_key * pubkey_p = NULL;
  esc_buf * key_data_p = NULL;
  esc_address addr = {
      .name = name, 
      .name_len = strlen(name), 
      .device_id = device_id
  };

  ret_val = signal_protocol_session_load_session(ctx_p->store_context_p, &sr_p, &addr);
  if (ret_val) {
    err_msg = "failed to load session";
    goto cleanup;
  }

  if (session_record_is_fresh(sr_p)) {
    goto cleanup;
  }

  ret_val = ec_public_key_serialize(&key_data_p, session_state_get_remote_identity_key(session_record_get_state(sr_p)));
  if (ret_val) {
    err_msg = "failed to serialize public key";
    goto cleanup;
  }

  ret_val = 1;
  *pubkey_data_pp = key_data_p;

cleanup:
  if (ret_val < 0) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
    esc_buf_free(key_data_p);
  }

  SIGNAL_UNREF(sr_p);
  SIGNAL_UNREF(pubkey_p);

  return ret_val;
}

*/
/*
esc_buf * esc_handshake_get_data(esc_handshake * handshake_p) {
  return handshake_p->handshake_msg_p;
}

*/

const char * create_pre_key_bundle(esc_address *address, esc_context *ctx_p, session_pre_key_bundle **bundle) {
  
    int ret;
    const char * err_msg = NULL;
    signal_protocol_store_context *store = ctx_p->store_context_p;

    uint32_t signed_pre_key_id;
    signal_protocol_identity_get_local_registration_id(store, &signed_pre_key_id);

    ratchet_identity_key_pair *our_identity_key = NULL;
    session_pre_key *pre_key_record = NULL;
    ratchet_identity_key_pair *identity_key_pair = NULL;    

    int unsigned_pre_key_id = 0;
    ec_public_key *signed_pre_key_public = NULL;

    signal_buffer *signed_pre_key_public_serialized = NULL; 
    signal_buffer *signature = NULL;       
    session_pre_key_bundle *pre_key_bundle = NULL;    
    session_signed_pre_key *signed_pre_key_record = NULL;    

    ret = signal_protocol_identity_get_key_pair(store, &our_identity_key);
    if (ret<0) {      
      return "cant_get_identity_key_pair";
    }

    signal_buffer *public_data, *private_data;
    esc_db_identity_get_key_pair(&public_data, &private_data, ctx_p);

    ec_key_pair *signed_pre_key;
    ec_key_pair_create(&signed_pre_key, ratchet_identity_key_pair_get_public(our_identity_key), ratchet_identity_key_pair_get_private(our_identity_key));
             
    int result = 0;

    ec_key_pair *unsigned_pre_key = 0;
    result = curve_generate_key_pair(ctx_p->global_context_p, &unsigned_pre_key);
    if (result!=0) {
      err_msg = "cant_generate_key_pair";
      goto cleanup;
    }
    
    unsigned_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;

    result = signal_protocol_identity_get_key_pair(store, &identity_key_pair);   
    if (result!=0) {
      err_msg = "cant_get_identity_pair";
      goto cleanup;
    }

    signed_pre_key_public = ec_key_pair_get_public(signed_pre_key);

    result = ec_public_key_serialize(&signed_pre_key_public_serialized, signed_pre_key_public);
    if (result!=0) {
      err_msg = "cant_serialize_public_key";
      goto cleanup;
    }

    result = curve_calculate_signature(ctx_p->global_context_p, &signature,
            ratchet_identity_key_pair_get_private(identity_key_pair),
            signal_buffer_data(signed_pre_key_public_serialized),
            signal_buffer_len(signed_pre_key_public_serialized));
    if (result!=0) {
      err_msg = "cant_calculate_curve_signature";
      goto cleanup;
    }   

    result = session_pre_key_bundle_create(&pre_key_bundle,
            1, // registration_id
            address->device_id,
            unsigned_pre_key_id,
            ec_key_pair_get_public(unsigned_pre_key),
            signed_pre_key_id, signed_pre_key_public,
            signal_buffer_data(signature), signal_buffer_len(signature),
            ratchet_identity_key_pair_get_public(identity_key_pair));
    if (result!=0) {
      err_msg = "cant_create_session_pre_key_bundle";
      goto cleanup;
    }             
   
    result = session_signed_pre_key_create(&signed_pre_key_record,
            signed_pre_key_id, time(0), signed_pre_key,
            signal_buffer_data(signature), signal_buffer_len(signature));
    if (result!=0) {
      err_msg = "cant_create_session_signed_pre_key";
      goto cleanup;
    }    

    result = signal_protocol_signed_pre_key_store_key(store, signed_pre_key_record);
    if (result!=0) {
      err_msg = "cant_store_session_signed_pre_key";
      goto cleanup;
    }      

    result = session_pre_key_create(&pre_key_record, unsigned_pre_key_id, unsigned_pre_key);
    if (result!=0) {
      err_msg = "cant_create_session_pre_key";
      goto cleanup;
    }         

    result = signal_protocol_pre_key_store_key(store, pre_key_record);
    if (result!=0) {
      err_msg = "cant_store_pre_key";
      goto cleanup;
    }         

cleanup:
    SIGNAL_UNREF(our_identity_key);
    SIGNAL_UNREF(pre_key_record);
    SIGNAL_UNREF(signed_pre_key_record);
    SIGNAL_UNREF(identity_key_pair);
    SIGNAL_UNREF(unsigned_pre_key);
    signal_buffer_free(signed_pre_key_public_serialized);
    signal_buffer_free(signature);

    *bundle = (err_msg == NULL) ? pre_key_bundle : NULL;

    return err_msg;
}

int session_pre_key_bundle_deserialize(esc_buf *buf, esc_context *ctx_p, session_pre_key_bundle **pre_key_bundle, esc_address **address_from ) {
    int result = 0;
    uint32_t registration_id;  // any number - not used in our case - lets set it to 0   
    uint32_t device_id;
    uint32_t username_len;
    uint8_t username[50] = {0};
    uint32_t pre_key_id;
    ec_public_key * pre_key_public;
    uint32_t signed_pre_key_id;
    ec_public_key * signed_pre_key_public;
    uint32_t signed_pre_key_signature_len;
    uint8_t signed_pre_key_signature[64];
    ec_public_key * identity_key;
  
    es_log("a1");
    unsigned char * msg = esc_buf_get_data(buf);
    int buf_len = esc_buf_get_len(buf);

    if (buf_len<12) {
      return -10000;
    }

    memcpy(&registration_id, &msg[0], 4);

    memcpy(&device_id, &msg[4], 4);

    memcpy(&username_len, &msg[8], 4);

    char *name = (char *) malloc(username_len+1);    

    memset(name, 0, username_len+1);

    if (12+username_len>buf_len) {
        return -10000;
    }

    memcpy(name, &msg[12], username_len);

    //es_log_hex("address: ", name, username_len);    

    uint16_t idx = 12 + username_len;
    if (idx+4>buf_len) {
        return -10000;
    }
    memcpy(&pre_key_id, &msg[idx], 4);

    idx += 4;
    if (idx+33>buf_len) {
        return -10000;
    }
    result = curve_decode_point(&pre_key_public, &msg[idx], 33, ctx_p->global_context_p);
    if (result!=0) {
        return result;
    }

    idx += 33;
    if (idx+4>buf_len) {
        return -10000;
    }
    memcpy(&signed_pre_key_id, &msg[idx], 4);

    idx += 4;
    if (idx+33>buf_len) {
        return -10000;
    }

    result = curve_decode_point(&signed_pre_key_public, &msg[idx], 33, ctx_p->global_context_p);
    if (result!=0) {
      return result;      
    }
    
    idx += 33;
    if (idx+4>buf_len) {
        return -10000;
    }
    memcpy(&signed_pre_key_signature_len, &msg[idx], 4);

    idx += 4;
    if (idx+signed_pre_key_signature_len>buf_len) {
        return -10000;
    }

    if (signed_pre_key_signature_len > 64) {
      return -10010;
    }

    memcpy(signed_pre_key_signature, &msg[idx], signed_pre_key_signature_len);
    idx += signed_pre_key_signature_len;
    if (idx+33>buf_len) {
        return -10000;
    }

    result = curve_decode_point(&identity_key, &msg[idx], 33, ctx_p->global_context_p);
    if (result!=0) {
      return result;
    }

    idx += 33;
    int response_len = 123+username_len+signed_pre_key_signature_len;    
    if (idx != response_len) {
      es_log(std::string(std::to_string(idx)).c_str());
      es_log(std::string(std::to_string(response_len)).c_str());
      return -10001;
    }

    session_pre_key_bundle *bundle;

    result = session_pre_key_bundle_create(&bundle,
            registration_id, // registration ID
            device_id, /* device ID */
            pre_key_id, /* pre key ID */
            pre_key_public,
            signed_pre_key_id, /* signed pre key ID */
            signed_pre_key_public,
            signed_pre_key_signature,
            (size_t)signed_pre_key_signature_len,
            identity_key);
    if (result!=0) {
      return result;
    }
    
    esc_address *address = (esc_address *) malloc(sizeof(esc_address));

    address->name_len = username_len;
    address->name = name;  
    address->device_id = device_id;

    *pre_key_bundle = bundle;
    *address_from = address;

    es_log("a2");
    return 0;
}

const char * session_pre_key_bundle_serialize(session_pre_key_bundle *bundle, esc_address *address_from, esc_context *ctx_p, esc_buf **buf ) {
  int len = 0;

  uint32_t registration_id = session_pre_key_bundle_get_registration_id(bundle);  // any number - not used in our case - lets set it to 0   
  uint32_t device_id = session_pre_key_bundle_get_device_id(bundle);
  uint32_t pre_key_id = session_pre_key_bundle_get_pre_key_id(bundle);
  ec_public_key * pre_key_public = session_pre_key_bundle_get_pre_key(bundle);
  uint32_t signed_pre_key_id = session_pre_key_bundle_get_signed_pre_key_id(bundle);
  ec_public_key * signed_pre_key_public = session_pre_key_bundle_get_signed_pre_key(bundle);

  signal_buffer *signature = session_pre_key_bundle_get_signed_pre_key_signature(bundle);
  uint32_t signed_pre_key_signature_len = signal_buffer_len(signature);
  if (signed_pre_key_signature_len>64) {
    return "bad_signed_pre_key_signature_len";
  }

  uint8_t *signed_pre_key_signature = signal_buffer_data(signature);
  ec_public_key * identity_key = session_pre_key_bundle_get_identity_key(bundle);

  int response_len = 123+address_from->name_len+signed_pre_key_signature_len;
  char *msg = (char *) malloc(response_len);
  memset(msg, 0, response_len);  

  memcpy(&msg[0], &registration_id, 4);

  memcpy(&msg[4], &device_id, 4);

  es_log_hex("ser_device_id:", ( char * ) &device_id, 4);

  memcpy(&msg[8], &address_from->name_len, 4);

  memcpy(&msg[12], address_from->name, address_from->name_len);

  es_log_hex("address: ", address_from->name, address_from->name_len);

  size_t idx = 12 + address_from->name_len;
  memcpy(&msg[idx], &pre_key_id, 4);

  idx += 4;
  esc_buf *b;
  ec_public_key_serialize(&b, pre_key_public);

  if (esc_buf_get_len(b) != 33) {
    return "bad_pre_key_public";
  }
  
  memcpy(&msg[idx], esc_buf_get_data(b), 33);
  esc_buf_free(b);

  idx += 33;
  memcpy(&msg[idx], &signed_pre_key_id, 4);

  idx += 4;
  ec_public_key_serialize(&b, signed_pre_key_public);

  if (esc_buf_get_len(b) != 33) {
    return "bad_signed_pre_key_public";
  }
  memcpy(&msg[idx], esc_buf_get_data(b), 33);
  esc_buf_free(b);

  idx += 33;
  memcpy(&msg[idx], &signed_pre_key_signature_len, 4);

  idx += 4;
  memcpy(&msg[idx], signed_pre_key_signature, signed_pre_key_signature_len);

  idx += signed_pre_key_signature_len;
  ec_public_key_serialize(&b, identity_key);

  if (esc_buf_get_len(b) != 33) {
    return "bad_identity_key";
  }

  memcpy(&msg[idx], esc_buf_get_data(b), 33);

  esc_buf_free(b);

  idx += 33;

  if (idx != response_len) {
    return "bad_serialisation_of_bundle";
  }

  *buf = signal_buffer_create((uint8_t *) msg, response_len);

  return NULL;
}

// Alice initate session with Bob
const char * esc_handshake_initiate(esc_address *sender_addr_p, esc_address *recipient_addr_p, esc_context * ctx_p, session_cipher **cipher, session_builder **builder, esc_buf **response) {
    const char *err_msg;
    int result;

    //* Create the session builder * /
    session_builder *alice_session_builder = NULL;
    result = session_builder_create(&alice_session_builder, ctx_p->store_context_p, recipient_addr_p, ctx_p->global_context_p);
  
    //* Create the session ciphers * /
    session_cipher *alice_session_cipher = NULL;
    result = session_cipher_create(&alice_session_cipher, ctx_p->store_context_p, recipient_addr_p, ctx_p->global_context_p);
    if (result < 0) {
      return "cant_create_session_cipher";
    }

    session_pre_key_bundle *alice_pre_key_bundle;
    err_msg = create_pre_key_bundle(sender_addr_p, ctx_p, &alice_pre_key_bundle);
    if (err_msg!=NULL) {
      return err_msg;
    }

    esc_buf *message;
    
    err_msg = session_pre_key_bundle_serialize(alice_pre_key_bundle, sender_addr_p, ctx_p, &message);
    if (err_msg!=NULL) {
      // TODO: Clean resources
      return err_msg;
    }
    
    *builder = alice_session_builder;
    *response = message;
    *cipher = alice_session_cipher;

  return NULL;
}

// Bob accepts bundle from Alice
const char * esc_handshake_accept(esc_buf * msg_data_p, esc_address * sender_addr_p, esc_context * ctx_p, session_cipher **cipher, session_builder **builder, esc_address ** address_from_p, esc_buf **response) {
    int result;
    const char *err_msg = NULL;

    session_pre_key_bundle *alice_pre_key_bundle = NULL;
    esc_address *address_from = NULL;
    es_log("1");
    result = session_pre_key_bundle_deserialize(msg_data_p, ctx_p, &alice_pre_key_bundle, &address_from);
    if (result!= 0) {
      free(address_from);
      return "bad_handshake";
    }
    
    session_builder *bob_session_builder = NULL;
    result = session_builder_create(&bob_session_builder, ctx_p->store_context_p, address_from, ctx_p->global_context_p);
    if (result!=0) {
      return "cant_make_session_builder";
    }

    //* Create the session ciphers * /
    session_cipher *bob_session_cipher = NULL;
    result = session_cipher_create(&bob_session_cipher, ctx_p->store_context_p, address_from, ctx_p->global_context_p);
    if (result!=0) {
      return "cant_make_session_cipher";
    }
   
    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle);
    if (result!=0) {
      return "cant_process_pre_key_bundle";
    }

    session_pre_key_bundle *bob_pre_key_bundle;
    err_msg = create_pre_key_bundle(sender_addr_p, ctx_p, &bob_pre_key_bundle);
    if (err_msg!=NULL) {
      return err_msg;
    }


    esc_buf *message;
    err_msg = session_pre_key_bundle_serialize(bob_pre_key_bundle, sender_addr_p, ctx_p, &message);
    if (err_msg!=NULL) {
      return err_msg;
    }    

    *builder = bob_session_builder;
    *response = message;
    *cipher = bob_session_cipher;
    *address_from_p = address_from; 

  return NULL;
}

// Alice gets Bob's bundle
const char * esc_handshake_acknowledge(esc_buf * msg_data_p, esc_address *address, esc_context * ctx_p, session_cipher **cipher, esc_address **address_from_p) {
    int result;
    const char *err_msg = NULL;

    session_pre_key_bundle *bob_pre_key_bundle = NULL;
    esc_address *address_from = NULL;

    result = session_pre_key_bundle_deserialize(msg_data_p, ctx_p, &bob_pre_key_bundle, &address_from);
    if (result!= 0) {
      free(address_from);
      return "bad_handshake";
    }

    session_builder *alice_builder = NULL;
    result = session_builder_create(&alice_builder, ctx_p->store_context_p, address_from, ctx_p->global_context_p);
    if (result!=0) {
      return "cant_make_session_builder";
    }    
   
    result = session_builder_process_pre_key_bundle(alice_builder, bob_pre_key_bundle);
    if (result!=0) {
      return "cant_process_pre_key_bundle";
    }    

    //* Create the session ciphers * /
    session_cipher *alice_session_cipher = NULL;
    result = session_cipher_create(&alice_session_cipher, ctx_p->store_context_p, address_from, ctx_p->global_context_p);
    if (result!=0) {
      return "cant_make_session_cipher";
    }

    // esc_address *address = (esc_address *) malloc(sizeof(esc_address));

    *address_from_p = address_from;
    *cipher = alice_session_cipher;

    return NULL;
}


/**
void init() {

    signal_context *store->;
    signal_context_create(&store->, user_data);
    signal_context_set_crypto_provider(store->, &provider);
    signal_context_set_locking_functions(store->, lock_function, unlock_function);
}
**/