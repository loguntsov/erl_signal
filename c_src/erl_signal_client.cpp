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

void recursive_mutex_lock(void * user_data);
void recursive_mutex_unlock(void * user_data);


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

  ret_val = signal_protocol_signed_pre_key_load_key(ctx_p->axolotl_store_context_p, &signed_prekey_p, signed_prekey_id);
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

  ret_val = signal_protocol_identity_get_key_pair(ctx_p->axolotl_store_context_p, &identity_key_pair_p);
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
  return ctx_p != NULL ? ctx_p->axolotl_global_context_p : NULL;
}

void esc_context_destroy_all(esc_context * ctx_p) {
/**
  if (ctx_p) {
    signal_context_destroy(ctx_p->axolotl_global_context_p);
    signal_protocol_store_context_destroy(ctx_p->axolotl_store_context_p);
    esc_mutexes_destroy(ctx_p->mutexes_p);

    free(ctx_p->db_filename);
  }
**/  
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

uint8_t * esc_buf_get_data(esc_buf * buf) {
  return signal_buffer_data(buf);
}

size_t esc_buf_get_len(esc_buf * buf) {
  return signal_buffer_len(buf);
}

void esc_buf_free(esc_buf * buf) {
  signal_buffer_bzero_free(buf);
}

int esc_init(esc_context * ctx_p) {
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
  if (signal_context_create(&(ctx_p->axolotl_global_context_p), ctx_p)) {
    err_msg = "failed to create global axolotl context";
    ret_val = -1;
    goto cleanup;
  }
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: created and set axolotl context", __func__);

  if (signal_context_set_crypto_provider(ctx_p->axolotl_global_context_p, &crypto_provider)) {
    err_msg = "failed to set crypto provider";
    ret_val = -1;
    goto cleanup;
  }
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: set axolotl crypto provider", __func__);

  // 3. set locking functions
  #ifndef NO_THREADS
  if (signal_context_set_locking_functions(ctx_p->axolotl_global_context_p, recursive_mutex_lock, recursive_mutex_unlock)) {
    err_msg = "failed to set locking functions";
    ret_val = -1;
    goto cleanup;
  }
  esc_log(ctx_p, ESC_LOG_DEBUG, "%s: set locking functions", __func__);
  #endif

  // init store context

  if (signal_protocol_store_context_create(&store_context_p, ctx_p->axolotl_global_context_p)) {
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

  ctx_p->axolotl_store_context_p = store_context_p;
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
  const char * err_msg = "";
  int ret_val = 0;
  int db_needs_init = 0;

  signal_context * global_context_p = ctx_p->axolotl_global_context_p;
  ratchet_identity_key_pair * identity_key_pair_p = NULL;
  signal_protocol_key_helper_pre_key_list_node * pre_keys_head_p = NULL;
  session_pre_key * last_resort_key_p = NULL;
  session_signed_pre_key * signed_pre_key_p = NULL;
  signal_buffer * last_resort_key_buf_p = NULL;
  signal_buffer * signed_pre_key_data_p = NULL;
  uint32_t registration_id;

  esc_log(ctx_p, ESC_LOG_INFO, "%s: calling install-time functions", __func__);

  int init_status = 0;
  int db_needs_reset = 0;

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

  if (db_needs_init) {
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: db needs init", __func__ );
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: setting init status to esc_DB_NEEDS_ROLLBACK (%i)", __func__, ESC_DB_NEEDS_ROLLBACK );

    ret_val = esc_db_init_status_set(ESC_DB_NEEDS_ROLLBACK, ctx_p);
    if (ret_val) {
      err_msg = "failed to set init status to esc_DB_NEEDS_ROLLBACK";
      goto cleanup;
    }

    ret_val = signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair_p, global_context_p);
    if (ret_val) {
      err_msg = "failed to generate the identity key pair";
      goto cleanup;
    }
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: generated identity key pair", __func__ );

    ret_val = signal_protocol_key_helper_generate_registration_id(&registration_id, 1, global_context_p);
    if (ret_val) {
      err_msg = "failed to generate registration id";
      goto cleanup;
    }
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: generated registration id: %i", __func__, registration_id);

    ret_val = signal_protocol_key_helper_generate_pre_keys(&pre_keys_head_p, 1, ESC_PRE_KEYS_AMOUNT, global_context_p);
    if(ret_val) {
      err_msg = "failed to generate pre keys";
      goto cleanup;
    }
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: generated pre keys", __func__ );

/*
    ret_val = signal_protocol_key_helper_generate_last_resort_pre_key(&last_resort_key_p, global_context_p);
    if (ret_val) {
      err_msg = "failed to generate last resort pre key";
      goto cleanup;
    }
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: generated last resort pre key", __func__ );
*/    

    ret_val = signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key_p, identity_key_pair_p, 0, g_get_real_time(), global_context_p);
    if (ret_val) {
      err_msg = "failed to generate signed pre key";
      goto cleanup;
    }
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: generated signed pre key", __func__ );


    ret_val = esc_db_identity_set_key_pair(identity_key_pair_p, ctx_p);
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

    ret_val = esc_db_pre_key_store_list(pre_keys_head_p, ctx_p);
    if (ret_val) {
      err_msg = "failed to save pre key list";
      goto cleanup;
    }
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: saved pre keys", __func__ );


    ret_val = session_pre_key_serialize(&last_resort_key_buf_p, last_resort_key_p);
    if (ret_val) {
      err_msg = "failed to serialize last resort pre key";
      goto cleanup;
    }

    ret_val = esc_db_pre_key_store(session_pre_key_get_id(last_resort_key_p), signal_buffer_data(last_resort_key_buf_p), signal_buffer_len(last_resort_key_buf_p), ctx_p);
    if (ret_val) {
      err_msg = "failed to save last resort pre key";
      goto cleanup;
    }
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: saved last resort pre key", __func__ );

    ret_val = session_signed_pre_key_serialize(&signed_pre_key_data_p, signed_pre_key_p);
    if (ret_val) {
      err_msg = "failed to serialize signed pre key";
      goto cleanup;
    }

    ret_val = esc_db_signed_pre_key_store(session_signed_pre_key_get_id(signed_pre_key_p), signal_buffer_data(signed_pre_key_data_p), signal_buffer_len(signed_pre_key_data_p), ctx_p);
    if (ret_val) {
      err_msg = "failed to save signed pre key";
      goto cleanup;
    }
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: saved signed pre key", __func__ );

    ret_val = esc_db_init_status_set(ESC_DB_INITIALIZED, ctx_p);
    if (ret_val) {
      err_msg = "failed to set init status to esc_DB_INITIALIZED";
      goto cleanup;
    }
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: initialised DB", __func__ );

  } else {
    esc_log(ctx_p, ESC_LOG_DEBUG, "%s: db already initialized", __func__ );
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
}

int esc_get_device_id(esc_context * ctx_p, uint32_t * id_p) {
  return signal_protocol_identity_get_local_registration_id(ctx_p->axolotl_store_context_p, id_p);
}

int esc_message_encrypt_and_serialize(esc_buf * msg_p, const esc_address * recipient_addr_p, esc_context * ctx_p, esc_buf ** ciphertext_pp) {
  const char * err_msg = "";
  int ret_val = 0;

  session_cipher * cipher_p = NULL;
  ciphertext_message * cipher_msg_p = NULL;
  signal_buffer * cipher_msg_data_p = NULL;
  esc_buf * cipher_msg_data_cpy_p = NULL;

  if (!ctx_p) {
    fprintf(stderr, "%s: axc ctx is null!\n", __func__);
    return -1;
  }

  if (!msg_p) {
    err_msg = "could not encrypt because msg pointer is null";
    ret_val = -1;
    goto cleanup;
  }
  if (!recipient_addr_p) {
    err_msg = "could not encrypt because recipient addr pointer is null";
    ret_val = -1;
    goto cleanup;
  }
  if (!ciphertext_pp) {
    err_msg = "could not encrypt because ciphertext pointer is null";
    ret_val = -1;
    goto cleanup;
  }


  ret_val = session_cipher_create(&cipher_p, ctx_p->axolotl_store_context_p, recipient_addr_p, ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to create session cipher";
    goto cleanup;
  }

  ret_val = session_cipher_encrypt(cipher_p, esc_buf_get_data(msg_p), esc_buf_get_len(msg_p), &cipher_msg_p);
  if (ret_val) {
    err_msg = "failed to encrypt the message";
    goto cleanup;
  }

  cipher_msg_data_p = ciphertext_message_get_serialized(cipher_msg_p);
  cipher_msg_data_cpy_p = signal_buffer_copy(cipher_msg_data_p);

  if (!cipher_msg_data_cpy_p) {
    err_msg = "failed to copy cipher msg data";
    ret_val = -1;
    goto cleanup;
  }

  *ciphertext_pp = cipher_msg_data_cpy_p;

cleanup:
  if (ret_val < 0) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
    esc_buf_free(cipher_msg_data_cpy_p);
  }

  session_cipher_free(cipher_p);
  SIGNAL_UNREF(cipher_msg_p);

  return ret_val;
}

int esc_message_decrypt_from_serialized (esc_buf * msg_p, esc_address * sender_addr_p, esc_context * ctx_p, esc_buf ** plaintext_pp) {
  const char * err_msg = "";
  int ret_val = 0;

  //TODO: add session_cipher_set_decryption_callback maybe?
  //FIXME: check message type

  signal_message * ciphertext_p = NULL;
  session_cipher * cipher_p = NULL;
  esc_buf * plaintext_buf_p = NULL;

  if (!ctx_p) {
    fprintf(stderr, "%s: axc ctx is null!\n", __func__);
    return -1;
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

  ret_val = session_cipher_create(&cipher_p, ctx_p->axolotl_store_context_p, sender_addr_p, ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to create session cipher";
    goto cleanup;
  }

  ret_val = signal_message_deserialize(&ciphertext_p, esc_buf_get_data(msg_p), esc_buf_get_len(msg_p), ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to deserialize whisper msg";
    goto cleanup;
  }
  ret_val = session_cipher_decrypt_signal_message(cipher_p, ciphertext_p, NULL, &plaintext_buf_p);
  if (ret_val) {
    err_msg = "failed to decrypt cipher message";
    goto cleanup;
  }

  *plaintext_pp = plaintext_buf_p;

cleanup:
  if (ret_val < 0) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  session_cipher_free(cipher_p);
  SIGNAL_UNREF(ciphertext_p);

  return ret_val;
}

int esc_session_exists_initiated(const esc_address * addr_p, esc_context * ctx_p) {
  int ret_val = 0;
  const char * err_msg = "";

  session_record * session_record_p = NULL;
  session_state * session_state_p = NULL;

  //TODO: if there was no response yet, even though it is an established session it keeps sending prekeymsgs
  //      maybe that is "uninitiated" too?

  if(!signal_protocol_session_contains_session(ctx_p->axolotl_store_context_p, addr_p)) {
    return 0;
  }

  ret_val = signal_protocol_session_load_session(ctx_p->axolotl_store_context_p, &session_record_p, addr_p);
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

  ret_val = signal_protocol_session_get_sub_device_sessions(ctx_p->axolotl_store_context_p, &sess_l_p, name, strlen(name));
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
                               ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to deserialize public pre key";
    goto cleanup;
  }


  ret_val = curve_decode_point(&signed_pre_key_public_p,
                               esc_buf_get_data(signed_pre_key_public_serialized_p),
                               esc_buf_get_len(signed_pre_key_public_serialized_p),
                               ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to deserialize signed public pre key";
    goto cleanup;
  }

  ret_val = curve_decode_point(&identity_key_public_p,
                               esc_buf_get_data(identity_key_public_serialized_p),
                               esc_buf_get_len(identity_key_public_serialized_p),
                               ctx_p->axolotl_global_context_p);
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

  ret_val = session_builder_create(&session_builder_p, ctx_p->axolotl_store_context_p, remote_address_p, ctx_p->axolotl_global_context_p);
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
  ret_val = signal_protocol_session_delete_session(ctx_p->axolotl_store_context_p, &addr);
  if (ret_val) {
    esc_log(ctx_p, ESC_LOG_ERROR, "%s: failed to delete session for %s:%i", __func__, user, device_id);
  }

  return ret_val;
}

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


  ret_val = session_builder_create(&session_builder_p, ctx_p->axolotl_store_context_p, remote_address_p, ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to create session builder";
    goto cleanup;
  }


  ret_val = signal_protocol_session_load_session(ctx_p->axolotl_store_context_p, &session_record_p, remote_address_p);
  if (ret_val) {
    err_msg = "failed to load or create session record";
    goto cleanup;
  }


  ret_val = pre_key_signal_message_deserialize(&pre_key_msg_p,
                                                esc_buf_get_data(pre_key_msg_serialized_p),
                                                esc_buf_get_len(pre_key_msg_serialized_p),
                                                ctx_p->axolotl_global_context_p);
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
    ret_val = signal_protocol_key_helper_generate_pre_keys(&key_l_p, new_id, 1, ctx_p->axolotl_global_context_p);
    if (ret_val) {
      err_msg = "failed to generate a new key";
      goto cleanup;
    }

    new_id++;

  } while (signal_protocol_pre_key_contains_key(ctx_p->axolotl_store_context_p, session_pre_key_get_id(signal_protocol_key_helper_key_list_element(key_l_p))));



  ret_val = session_builder_process_pre_key_signal_message(session_builder_p, session_record_p, pre_key_msg_p, &pre_key_id);
  if (ret_val < 0) {
    err_msg = "failed to process pre key message";
    goto cleanup;
  }


  ret_val = session_cipher_create(&session_cipher_p, ctx_p->axolotl_store_context_p, remote_address_p, ctx_p->axolotl_global_context_p);
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

  ret_val = signal_protocol_pre_key_store_key(ctx_p->axolotl_store_context_p, signal_protocol_key_helper_key_list_element(key_l_p));
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

int esc_key_load_public_own(esc_context * ctx_p, esc_buf ** pubkey_data_pp) {
  const char * err_msg;
  int ret_val = 0;

  ratchet_identity_key_pair * kp_p = NULL;
  esc_buf * key_data_p = NULL;

  ret_val = signal_protocol_identity_get_key_pair(ctx_p->axolotl_store_context_p, &kp_p);
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

  ret_val = signal_protocol_session_load_session(ctx_p->axolotl_store_context_p, &sr_p, &addr);
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



/**
void init() {

    signal_context *global_context;
    signal_context_create(&global_context, user_data);
    signal_context_set_crypto_provider(global_context, &provider);
    signal_context_set_locking_functions(global_context, lock_function, unlock_function);
}
**/