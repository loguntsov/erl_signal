#include <stdint.h> // int types
#include <stdio.h> // printf
#include <stdlib.h> // exit
#include <string.h> // strlen

#include <iostream>
#include <algorithm>

#include "libsignal-c/signal_protocol.h"
#include "libsignal-c/key_helper.h"

// #include <sqlite3.h>

#include "erl_signal_client.h"
#include "erl_signal_store.h"


#define INIT_STATUS_NAME "init_status"
#define OWN_PUBLIC_KEY_NAME "own_public_key"
#define OWN_PRIVATE_KEY_NAME "own_private_key"
#define OWN_KEY 2
#define REG_ID_NAME "axolotl_registration_id"
#define IDENTITY_KEY_TRUSTED 1
#define IDENTITY_KEY_UNTRUSTED 1

#define SESSION_STORE_TABLE_NAME "session_store"
#define SESSION_STORE_NAME_NAME "name"
#define SESSION_STORE_NAME_LEN_NAME "name_len"
#define SESSION_STORE_DEVICE_ID_NAME "device_id"
#define SESSION_STORE_RECORD_NAME "session_record"
#define SESSION_STORE_RECORD_LEN_NAME "record_len"
#define PRE_KEY_STORE_TABLE_NAME "pre_key_store"
#define PRE_KEY_STORE_ID_NAME "id"
#define PRE_KEY_STORE_RECORD_NAME "pre_key_record"
#define PRE_KEY_STORE_RECORD_LEN_NAME "record_len"
#define SIGNED_PRE_KEY_STORE_TABLE_NAME "signed_pre_key_store"
#define SIGNED_PRE_KEY_STORE_ID_NAME "id"
#define SIGNED_PRE_KEY_STORE_RECORD_NAME "signed_pre_key_record"
#define SIGNED_PRE_KEY_STORE_RECORD_LEN_NAME "record_len"
#define IDENTITY_KEY_STORE_TABLE_NAME "identity_key_store"
#define IDENTITY_KEY_STORE_NAME_NAME "name"
#define IDENTITY_KEY_STORE_KEY_NAME "key"
#define IDENTITY_KEY_STORE_KEY_LEN_NAME "key_len"
#define IDENTITY_KEY_STORE_TRUSTED_NAME "trusted"
#define SETTINGS_STORE_TABLE_NAME "settings"
#define SETTINGS_STORE_NAME_NAME "name"
#define SETTINGS_STORE_PROPERTY_NAME "property"

int esc_db_property_set(const char * name, const int val, esc_context * esc_ctx_p) {
    esc_storage::value str = std::to_string(val);
    esc_storage::row row;
    row.store(esc_storage::column("p"), str);
    esc_ctx_p->settings->set(name, row);
    return 0;
}

int esc_db_property_get(const char * name, int * val_p, esc_context * esc_ctx_p) {
  const esc_storage::row row = esc_ctx_p->settings->get(std::string(name));
  esc_storage::value value = row.get(esc_storage::column("p"), "0");
  *val_p = std::stoi(value);
  return 0;
}

int esc_db_init_status_set(const int status, esc_context * esc_ctx_p) {
  return esc_db_property_set(INIT_STATUS_NAME, status, esc_ctx_p);
}

int esc_db_init_status_get(int * init_status_p, esc_context * esc_ctx_p) {
  return esc_db_property_get(INIT_STATUS_NAME, init_status_p, esc_ctx_p);
}

std::string broadcast_address_string(const signal_protocol_address *address) {
  return std::string(address->name, address->name_len);  
}

std::string address_string(const signal_protocol_address *address) {
  std::string str = broadcast_address_string(address);
  str.append("_").append(std::to_string(address->device_id));
  return str;
}


// session store impl
int esc_db_session_load(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data) {
  std::string key = address_string(address);
  esc_context * esc_ctx_p = (esc_context *) user_data;
  esc_storage::row row = esc_ctx_p->session_store->get(key);

  if (row.is_empty()) {
    *record = NULL;
    *user_record = NULL;
    return 1;
  }

  std::string session_record = row.get("session_record","");
  int session_record_len = std::stoi(row.get("session_record_len", "0"));
  *record = signal_buffer_create((const uint8_t *) session_record.c_str(), session_record_len);  

  std::string user_record_str = row.get("user_record","");
  int user_record_len = std::stoi(row.get("user_record_len", "0"));
  *user_record = signal_buffer_create((const uint8_t *) user_record_str.c_str(), user_record_len);  

  return 0;
}

int esc_db_session_get_sub_device_sessions(signal_int_list ** sessions, const char * name, size_t name_len, void * user_data) {

  std::string name_str = std::string(name, name_len);
  esc_context * esc_ctx_p = (esc_context *) user_data;

  std::list <esc_storage::row> result = esc_ctx_p->session_store->get_nearby(name_str);

  signal_int_list * session_list_p = signal_int_list_alloc();;

  for(std::list <esc_storage::row>::const_iterator iterator = result.begin(); iterator != result.end(); iterator++) {
      esc_storage::row row = *iterator;
      std::string device_id_str = row.get("device_id", "");
      if (device_id_str.size() > 0) {
        signal_int_list_push_back(session_list_p, std::stoi(device_id_str));
      }
  }

  *sessions = session_list_p;

  return signal_int_list_size(session_list_p);
}

int esc_db_session_store(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data) {
  esc_storage::row row;
  row.store(esc_storage::column("name"), esc_storage::value(address->name));
  row.store(esc_storage::column("name_len"), esc_storage::value(std::to_string(address->name_len)));
  
  row.store(esc_storage::column("device_id"), esc_storage::value(std::to_string(address->device_id)));

  row.store(esc_storage::column("session_record"), esc_storage::value(std::string((char *) record, record_len)));
  row.store(esc_storage::column("session_record_len"), esc_storage::value(std::to_string(record_len)));  

  row.store(esc_storage::column("user_record"), esc_storage::value(std::string((char *) user_record, user_record_len)));
  row.store(esc_storage::column("user_record_len"), esc_storage::value(std::to_string(user_record_len)));  

  esc_context * esc_ctx_p = (esc_context *) user_data;

  esc_ctx_p->session_store->set(address_string(address), row);

  return 0;
}

int esc_db_session_contains(const signal_protocol_address * address, void * user_data) {
  
  std::string key = address_string(address);
  esc_context * esc_ctx_p = (esc_context *) user_data;
  esc_storage::row row = esc_ctx_p->session_store->get(key);

  if (row.is_empty()) {
    return 0;
  } else {
    return 1;  
  }
}

int esc_db_session_delete(const signal_protocol_address * address, void * user_data) {

  std::string key = address_string(address);
  esc_context * esc_ctx_p = (esc_context *) user_data;
  esc_storage::row row = esc_ctx_p->session_store->get(key);  
  esc_ctx_p->session_store->erase(key);
  if (row.is_empty()) {
    return 0;
  } else {
    return 1;  
  }
}

int esc_db_session_delete_all(const char * name, size_t name_len, void * user_data) {

  std::string name_str = std::string(name, name_len);
  esc_context * esc_ctx_p = (esc_context *) user_data;

  return esc_ctx_p->session_store->erase_nearby(name_str);
}

void esc_db_session_destroy_store_ctx(void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  
  esc_ctx_p->session_store->clear();
}

// pre key store impl
int esc_db_pre_key_load(signal_buffer ** record, uint32_t pre_key_id, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;

  std::string key = std::to_string(pre_key_id);

  esc_storage::row row = esc_ctx_p->pre_key_store->get(key);

  if(row.is_empty()) {
    return SG_ERR_INVALID_KEY_ID;
  }

  std::string pre_key = row.get("pre_key","");
  int pre_key_len = std::stoi(row.get("pre_key_len", "0"));
  *record = signal_buffer_create((const uint8_t *) pre_key.c_str(), pre_key_len);  
  
  return SG_SUCCESS;
}

int esc_db_pre_key_store(uint32_t pre_key_id, uint8_t * record, size_t record_len, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  

  esc_storage::row row;
  row.store(esc_storage::column("pre_key"), std::string((char *) record, record_len));
  row.store(esc_storage::column("pre_key_len"), esc_storage::value(std::to_string(record_len)));

  std::string key = std::to_string(pre_key_id);

  esc_ctx_p->pre_key_store->set(key, row);

  return 0;
}

int esc_db_pre_key_store_list(signal_protocol_key_helper_pre_key_list_node * pre_keys_head, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  

  signal_protocol_key_helper_pre_key_list_node * pre_keys_curr_p = NULL;
  signal_buffer * key_buf_p = NULL;  
  session_pre_key * pre_key_p = NULL;

  pre_keys_curr_p = pre_keys_head;
  struct data {
    uint32_t id;
    std::string pre_key;
  };
  std::list <data> result;
  while (pre_keys_curr_p) {
    pre_key_p = signal_protocol_key_helper_key_list_element(pre_keys_curr_p);
    if (session_pre_key_serialize(&key_buf_p, pre_key_p)) {      
      return -1;
    }

    uint32_t pre_key_id = session_pre_key_get_id(pre_key_p);
    std::string pre_key = std::string((char *) signal_buffer_data(key_buf_p), signal_buffer_len(key_buf_p));
    data d = {
      .id = pre_key_id,
      .pre_key = pre_key
    };
    result.push_back(d);
    pre_keys_curr_p = signal_protocol_key_helper_key_list_next(pre_keys_curr_p);
  }

  for(std::list <data>::const_iterator iterator = result.begin(); iterator != result.end(); iterator++) {
    data d = *iterator;

    esc_storage::row row;
    row.store(esc_storage::column("pre_key"), d.pre_key);
    row.store(esc_storage::column("pre_key_len"), std::to_string(d.pre_key.length()));

    std::string key = std::to_string(d.id);

    esc_ctx_p->pre_key_store->set(key, row);
  }

  return 0;
}

int esc_db_pre_key_get_list(size_t amount, void * user_data, esc_buf_list_item ** list_head_pp) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  
  const char * err_msg;

  esc_buf_list_item *list = NULL;
  esc_buf_list_item *head = NULL;
  ec_key_pair * pre_key_pair_p = NULL;
  ec_public_key * pre_key_public_p = NULL;
  esc_buf * pre_key_public_serialized_p = NULL;
  esc_buf_list_item * temp_item_p = NULL;

  int ret_val = 0;

  session_pre_key * pre_key_p = NULL;  

  for(esc_storage::storage::const_iterator it = esc_ctx_p->pre_key_store->begin(); it!=esc_ctx_p->pre_key_store->end(); it++) {
    uint32_t key_id = std::stoi(it->first);
    esc_storage::row row = it->second;

    std::string pre_key_str_serialized = row.get("pre_key", "");

    ret_val = session_pre_key_deserialize(&pre_key_p, (uint8_t *) pre_key_str_serialized.c_str(), pre_key_str_serialized.size(), esc_ctx_p->global_context_p);
    if (ret_val) {
      err_msg = "failed to deserialize pre_key";
      goto cleanup;
    }    

    pre_key_pair_p = session_pre_key_get_key_pair(pre_key_p);
    pre_key_public_p = ec_key_pair_get_public(pre_key_pair_p);

    ret_val = ec_public_key_serialize(&pre_key_public_serialized_p, pre_key_public_p);
    if (ret_val) {
      err_msg = "failed to serialize public key";
      goto cleanup;
    }

    ret_val = esc_buf_list_item_create(&temp_item_p, &key_id, pre_key_public_serialized_p);
    if (ret_val) {
      err_msg = "failed to create list item";
      goto cleanup;
    }

    //esc_buf_free(serialized_keypair_data_p);

    SIGNAL_UNREF(pre_key_p);
    pre_key_p = NULL;

    esc_buf_list_item_create(&head, NULL, NULL);
    head->next_p = list;
    list = head;
  }

/**  
  const char stmt[] = "SELECT * FROM " PRE_KEY_STORE_TABLE_NAME
                      " ORDER BY " PRE_KEY_STORE_ID_NAME " ASC LIMIT ?1;";

  int ret_val = -1;
  char * err_msg = NULL;

  sqlite3 * db_p = NULL;
  sqlite3_stmt * pstmt_p = NULL;
  esc_buf_list_item * head_p = NULL;
  esc_buf_list_item * curr_p = NULL;
  uint32_t key_id = 0;
  esc_buf * serialized_keypair_data_p = NULL;
  size_t record_len = 0;

  ec_key_pair * pre_key_pair_p = NULL;
  ec_public_key * pre_key_public_p = NULL;
  esc_buf * pre_key_public_serialized_p = NULL;
  esc_buf_list_item * temp_item_p = NULL;

  if (db_conn_open(&db_p, &pstmt_p, stmt, esc_ctx_p)) return -1;

  ret_val = sqlite3_bind_int(pstmt_p, 1, amount);
  if (ret_val) {
    err_msg = "failed to bind";
    goto cleanup;
  }

  ret_val = esc_buf_list_item_create(&head_p, NULL, NULL);
  if (ret_val) {
    err_msg = "failed to create list";
    goto cleanup;
  }

  curr_p = head_p;
  ret_val = sqlite3_step(pstmt_p);
  while (ret_val == SQLITE_ROW) {
    key_id = sqlite3_column_int(pstmt_p, 0);
    record_len = sqlite3_column_int(pstmt_p, 2);

    serialized_keypair_data_p = signal_buffer_create(sqlite3_column_blob(pstmt_p, 1), record_len);
    if (!serialized_keypair_data_p) {
      err_msg = "failed to initialize buffer";
      ret_val = -3;
      goto cleanup;
    }

    ret_val = session_pre_key_deserialize(&pre_key_p, esc_buf_get_data(serialized_keypair_data_p), record_len, esc_context_get_axolotl_ctx(esc_ctx_p));
    if (ret_val) {
      err_msg = "failed to deserialize keypair";
      goto cleanup;
    }

    pre_key_pair_p = session_pre_key_get_key_pair(pre_key_p);
    pre_key_public_p = ec_key_pair_get_public(pre_key_pair_p);

    ret_val = ec_public_key_serialize(&pre_key_public_serialized_p, pre_key_public_p);
    if (ret_val) {
      err_msg = "failed to serialize public key";
      goto cleanup;
    }

    ret_val = esc_buf_list_item_create(&temp_item_p, &key_id, pre_key_public_serialized_p);
    if (ret_val) {
      err_msg = "failed to create list item";
      goto cleanup;
    }

    esc_buf_list_item_set_next(curr_p, temp_item_p);
    curr_p = esc_buf_list_item_get_next(curr_p);

    esc_buf_free(serialized_keypair_data_p);

    SIGNAL_UNREF(pre_key_p);
    pre_key_p = NULL;
    ret_val = sqlite3_step(pstmt_p);
  }

  if (ret_val != SQLITE_DONE) {
    err_msg = "sql error when retrieving keys";
    goto cleanup;
  }

  *list_head_pp = esc_buf_list_item_get_next(head_p);
  ret_val = 0;
*/
cleanup:
  if (ret_val) {
    //esc_buf_free(serialized_keypair_data_p);
    SIGNAL_UNREF(pre_key_p);
    esc_buf_free(pre_key_public_serialized_p);
    esc_buf_list_free(list);
    return ret_val;    
  } else {
      *list_head_pp = list;
      (void *) err_msg;
      return 0;      
  }

  
}

int esc_db_pre_key_contains(uint32_t pre_key_id, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  

  std::string key = std::to_string(pre_key_id);
  if(esc_ctx_p->pre_key_store->is_member(key)) {
    return 1;
  } else {
    return 0;
  }
}

int esc_db_pre_key_get_max_id(void * user_data, uint32_t * max_id_p) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  

  std::list <esc_storage::key> keys = esc_ctx_p->pre_key_store->keys();

  std::list <uint32_t> ids;

  for(std::list <esc_storage::key>::const_iterator it = keys.begin(); it != keys.end(); it++) {
    ids.push_front((uint32_t) std::stoi(*it));
  }

  *max_id_p = *std::max_element(ids.begin(), ids.end());
  return 0;
}

int esc_db_pre_key_get_count(void * user_data, size_t * count_p) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  

  std::list <esc_storage::key> keys = esc_ctx_p->pre_key_store->keys();

  *count_p = esc_ctx_p->pre_key_store->size();
  return 0;
}

int esc_db_pre_key_remove(uint32_t pre_key_id, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  

  std::string key = std::to_string(pre_key_id);

  bool is_member = esc_ctx_p->pre_key_store->is_member(key);
  esc_ctx_p->pre_key_store->erase(key);
  if (is_member) {
    return 0;
  } else {
    return -4;
  }
}
  
void esc_db_pre_key_destroy_ctx(void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;

  esc_ctx_p->pre_key_store->clear();
}

// signed pre key store impl
int esc_db_signed_pre_key_load(signal_buffer ** record, uint32_t signed_pre_key_id, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;

  std::string key = std::to_string(signed_pre_key_id);

  esc_storage::row row = esc_ctx_p->signed_pre_key_store->get(key);

  if(row.is_empty()) {
    return SG_ERR_INVALID_KEY_ID;
  }

  std::string signed_pre_key = row.get("signed_pre_key","");
  int pre_key_len = std::stoi(row.get("signed_pre_key_len", "0"));
  *record = signal_buffer_create((const uint8_t *) signed_pre_key.c_str(), pre_key_len);  
  
  return SG_SUCCESS;
}

int esc_db_signed_pre_key_store(uint32_t signed_pre_key_id, uint8_t * record, size_t record_len, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  

  esc_storage::row row;
  row.store(esc_storage::column("signed_pre_key"), std::string((char *) record, record_len));
  row.store(esc_storage::column("signed_pre_key_len"), esc_storage::value(std::to_string(record_len)));

  std::string key = std::to_string(signed_pre_key_id);

  esc_ctx_p->signed_pre_key_store->set(key, row);

  return 0;
}

int esc_db_signed_pre_key_contains(uint32_t signed_pre_key_id, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  

  std::string key = std::to_string(signed_pre_key_id);
  if(esc_ctx_p->signed_pre_key_store->is_member(key)) {
    return 1;
  } else {
    return 0;
  }
}

int esc_db_signed_pre_key_remove(uint32_t signed_pre_key_id, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  

  std::string key = std::to_string(signed_pre_key_id);

  bool is_member = esc_ctx_p->signed_pre_key_store->is_member(key);
  esc_ctx_p->pre_key_store->erase(key);
  if (is_member) {
    return 0;
  } else {
    return -4;
  }
}

void esc_db_signed_pre_key_destroy_ctx(void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;

  esc_ctx_p->signed_pre_key_store->clear();

}

// identity key store impl
/**
 * saves the public and private key by using the api serialization calls, as this format (and not the higher-level key type) is needed by the getter.
 */
int esc_db_identity_set_key_pair(const ratchet_identity_key_pair * key_pair_p, void * user_data) {
  // 1 - name ("public" or "private")
  // 2 - key blob
  // 3 - length of the key
  // 4 - trusted (1 for true, 0 for false)

  esc_context * esc_ctx_p = (esc_context *) user_data;
  int ret_val = 0;
  //const char * err_msg = NULL;  

  esc_storage::row row_public;
  signal_buffer * pubkey_buf_p = NULL;
  size_t pubkey_buf_len = 0;
  uint8_t * pubkey_buf_data_p = NULL;  

  esc_storage::row row_private;
  signal_buffer * privkey_buf_p = NULL;  
  size_t privkey_buf_len = 0;
  uint8_t * privkey_buf_data_p = NULL;

  if (ec_public_key_serialize(&pubkey_buf_p, ratchet_identity_key_pair_get_public(key_pair_p))) {
    //err_msg = "Failed to allocate memory to serialize the public key";
    ret_val = SG_ERR_NOMEM;
    goto cleanup;
  }
  pubkey_buf_len = signal_buffer_len(pubkey_buf_p);
  pubkey_buf_data_p = signal_buffer_data(pubkey_buf_p);

  row_public.store("name", OWN_PUBLIC_KEY_NAME);
  row_public.store("blob", std::string((char *) pubkey_buf_data_p, pubkey_buf_len));
  row_public.store("blob_len", std::to_string(pubkey_buf_len));  
  row_public.store("trusted", std::to_string(OWN_KEY));

  esc_ctx_p->identity_key_store->set(OWN_PUBLIC_KEY_NAME, row_public);




  if (ec_private_key_serialize(&privkey_buf_p, ratchet_identity_key_pair_get_private(key_pair_p))) {
    //err_msg = "Failed to allocate memory to serialize the private key";
    ret_val = SG_ERR_NOMEM;
    goto cleanup;
  }

  privkey_buf_len = signal_buffer_len(privkey_buf_p);
  privkey_buf_data_p = signal_buffer_data(privkey_buf_p);  
  
  row_private.store("name", OWN_PRIVATE_KEY_NAME);
  row_private.store("blob", std::string((char *) privkey_buf_data_p, privkey_buf_len));
  row_private.store("blob_len", std::to_string(privkey_buf_len));  
  row_private.store("trusted", std::to_string(OWN_KEY));

  esc_ctx_p->identity_key_store->set(OWN_PRIVATE_KEY_NAME, row_private);  

cleanup:
  if (pubkey_buf_p) {
    signal_buffer_bzero_free(pubkey_buf_p);
  }
  if (privkey_buf_p) {
    signal_buffer_bzero_free(privkey_buf_p);
  }
  return ret_val;
}

int esc_db_identity_get_key_pair(signal_buffer ** public_data, signal_buffer ** private_data, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;
  int ret_val = 0;
  const char * err_msg = NULL;  

  esc_storage::row row_public = esc_ctx_p->identity_key_store->get(OWN_PUBLIC_KEY_NAME);
  signal_buffer * pubkey_buf_p = NULL;
  size_t pubkey_buf_len = 0;

  esc_storage::row row_private;
  std::string private_blob, public_blob;
  signal_buffer * privkey_buf_p = NULL;  
  size_t privkey_buf_len = 0;  
  
  if (row_public.is_empty()) {
    err_msg = "Own public key not found";
    ret_val = SG_ERR_INVALID_KEY_ID;
    goto cleanup;
  }

  public_blob = row_public.get("blob", "");
  pubkey_buf_len = std::stoi(row_public.get("blob_len", "0"));

  pubkey_buf_p = signal_buffer_create((uint8_t *) public_blob.c_str(), pubkey_buf_len);


  row_private = esc_ctx_p->identity_key_store->get(OWN_PRIVATE_KEY_NAME);
  
  if (row_private.is_empty()) {
    err_msg = "Own private key not found";
    ret_val = SG_ERR_INVALID_KEY_ID;
    goto cleanup;
  }

  private_blob = row_public.get("blob", "");
  privkey_buf_len = std::stoi(row_public.get("blob_len", "0"));

  privkey_buf_p = signal_buffer_create((uint8_t *) public_blob.c_str(), privkey_buf_len);

  *public_data = pubkey_buf_p;
  *private_data = privkey_buf_p;

cleanup:
  if (ret_val < 0) {
    if (pubkey_buf_p) {
      signal_buffer_bzero_free(pubkey_buf_p);
    }
    if (privkey_buf_p) {
      signal_buffer_bzero_free(privkey_buf_p);
    }
  }
  (void) err_msg;
  return ret_val;
}

int esc_db_identity_set_local_registration_id(const uint32_t reg_id, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;      
  return (esc_db_property_set(REG_ID_NAME, reg_id, esc_ctx_p)) ? -1 : 0;
}

int esc_db_identity_get_local_registration_id(void * user_data, uint32_t * registration_id) {
  esc_context * esc_ctx_p = (esc_context *) user_data;    
  return (esc_db_property_get(REG_ID_NAME, (int *) registration_id, esc_ctx_p ) != 0) ? -1 : 0;  
}

int esc_db_identity_save(const signal_protocol_address * addr_p, uint8_t * key_data, size_t key_len, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  
  std::string address = broadcast_address_string(addr_p);
  if (key_data) {
    std::string blob = std::string((char *) key_data, key_len);

    esc_storage::row row;
    row.store("name", address);
    row.store("blob", blob);
    row.store("blob_len", std::to_string(blob.size()));  
    row.store("trusted", std::to_string(IDENTITY_KEY_TRUSTED));

    esc_ctx_p->identity_key_store->set(address, row);
  } else {
    esc_ctx_p->identity_key_store->erase(address);
  }
  return 0;
}

int esc_db_identity_is_trusted(const char * name, size_t name_len, uint8_t * key_data, size_t key_len, void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;  
  std::string name_str = std::string(name, name_len);

  esc_storage::row row = esc_ctx_p->identity_key_store->get(name_str);
  std::string trusted = row.get("trusted", "");
  if (trusted == "") {
    return 1;
  }

  std::string key = std::string((char *) key_data, key_len);
  if (key == row.get("blob", "")) {
    return 1;
  } else {
    return 0;
  }  
}

int esc_db_identity_always_trusted(const signal_protocol_address * addr_p, uint8_t * key_data, size_t key_len, void * user_data) {
  return 1;
}

void esc_db_identity_destroy_ctx(void * user_data) {
  esc_context * esc_ctx_p = (esc_context *) user_data;
  esc_ctx_p->identity_key_store->clear();  
}
