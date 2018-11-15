#include <erl_nif.h>
#include <cstring>
#include <iostream>

#include "libsignal-c/signal_protocol.h"
#include "libsignal-c/session_builder.h"
#include "libsignal-c/session_cipher.h"

#include "erl_signal_client.h"
#include "erl_signal_client_storage.h"

#include "erl_signal_log.h"

typedef struct {
    esc_context * ctx_p;
} context_resource;

typedef struct {
    session_builder* session_builder_p = NULL;
} session_builder_resource;
 
typedef struct {
    session_cipher* session_cipher_p = NULL;
} session_cipher_resource;

extern "C" {

    static ErlNifResourceType* CONTEXT_RESOURCE;
    static ErlNifResourceType* SESSION_BUILDER_RESOURCE; 
    static ErlNifResourceType* SESSION_CIPHER_RESOURCE;

    ERL_NIF_TERM nif_esc_new(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    ERL_NIF_TERM nif_esc_generate_identity_keys(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    ERL_NIF_TERM nif_esc_is_session_exists_initiated(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    ERL_NIF_TERM nif_esc_handshake_initiate(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    ERL_NIF_TERM nif_esc_handshake_accept(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    ERL_NIF_TERM nif_esc_handshake_acknowledge(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    ERL_NIF_TERM nif_esc_encode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    ERL_NIF_TERM nif_esc_decode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);    
    ERL_NIF_TERM nif_esc_serialize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);        

}

ERL_NIF_TERM make_response(ErlNifEnv* env, const char * ErrorType, const char * Reason) {
    return enif_make_tuple2(env,
        enif_make_atom(env, ErrorType),
        enif_make_atom(env, Reason)
    );
}

bool erlnifterm_is_atom(ErlNifEnv* env, ERL_NIF_TERM term, const char * atom) {
    return enif_is_identical(term, enif_make_atom(env, atom));
}

const char * create_signal_protocol_address(ErlNifEnv* env, const ERL_NIF_TERM es_address, signal_protocol_address *result) {
    int arity; 
    const ERL_NIF_TERM *array = NULL; 

    if(!enif_get_tuple(env, es_address, &arity, &array)) { 
        return "address_is_not_tuple";
    }

    if (arity != 3) {
        return "address_tuple_is_bad";
    }
/*
    if (erlnifterm_is_atom(env, array[0], "es_address")) {
        return "bad_record";
    }
*/
    ErlNifBinary buffer;
    if (!enif_inspect_binary(env, array[1], &buffer)) {
	    return "name_is_not_binary";
    }
       
    unsigned int device_id;

    if (!enif_get_uint(env, array[2], &device_id)) {
        return "device_id_is_not_integer";
    }

    result->name = (char *) buffer.data;
    result->name_len = buffer.size;
    result->device_id = device_id;

    return NULL;
}

ERL_NIF_TERM construct_es_address_record(ErlNifEnv* env, esc_address *record) {
    ERL_NIF_TERM address_bin;
    ErlNifBinary binary;
    enif_alloc_binary(record->name_len, &binary);
    memcpy((char *) binary.data, (char *) record->name, record->name_len);    
    address_bin = enif_make_binary(env, &binary);
    return enif_make_tuple3(env,
        enif_make_atom(env, "es_address"),
        address_bin,
        enif_make_int(env, record->device_id)
    );
}

ERL_NIF_TERM nif_esc_new(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

    if (argc != 0 ) {
	    return enif_make_badarg(env);
    }

    context_resource * ctx_res_p = (context_resource*) enif_alloc_resource(CONTEXT_RESOURCE, sizeof(context_resource));
    
    if (ctx_res_p == NULL) {
        return make_response(env, "error", "cant_create_session");
    }

    int a = esc_context_create(&(ctx_res_p->ctx_p));
    if (a != 0 ) {
        return make_response(env, "error", "cant_create_context");
    }
    a = esc_init(ctx_res_p->ctx_p);
    if (a != 0) {
        return make_response(env, "error", "cant_init_context");
    }

	ERL_NIF_TERM result = enif_make_resource(env, ctx_res_p);
    //enif_release_resource(ctx_res_p);
    es_log("");    
    es_log("created new - ok");
	return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"), 
        result
    );
}

ERL_NIF_TERM nif_esc_generate_identity_keys(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {    
    context_resource *ctx_res_p = NULL;
    const char * err_msg = NULL;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_res_p)) {
        return enif_make_badarg(env);
    }
    err_msg = esc_generate_identity_keys(ctx_res_p->ctx_p);
    if (err_msg != NULL) {
        return enif_raise_exception(env, make_response(env, "badarg", err_msg));
    }
    return enif_make_atom(env, "ok");
}

ERL_NIF_TERM nif_esc_is_session_exists_initiated(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
   
    context_resource *ctx_res_p = NULL;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_res_p)) {
        return enif_make_badarg(env);
    }

    signal_protocol_address *address = new signal_protocol_address();
    
    const char * ret_val = create_signal_protocol_address(env, argv[1], address);
    if(ret_val != NULL) {
        return enif_raise_exception(env,
            make_response(env, "error", ret_val)
        );
    }
    
    int r = esc_session_exists_initiated(address, ctx_res_p->ctx_p);

    if (r==0) return enif_make_atom(env, "false");
    if (r==1) return enif_make_atom(env, "true");
    
    return enif_raise_exception(env, enif_make_tuple3(env,
        enif_make_atom(env, "error"),
        enif_make_atom(env, "bad_initialisation_result"),
        enif_make_int(env, r)
    ));
}

ERL_NIF_TERM nif_esc_handshake_initiate(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    context_resource *ctx_res_p = NULL;
    const char * err_msg;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_res_p)) {
        return enif_make_badarg(env);
    }

    signal_protocol_address sender_address;
    const char * ret_val = create_signal_protocol_address(env, argv[1], &sender_address);
    if(ret_val != NULL) {
        return enif_raise_exception(env,
            make_response(env, "error", ret_val)
        );
    }

    signal_protocol_address recepient_address;
    ret_val = create_signal_protocol_address(env, argv[2], &recepient_address);
    if(ret_val != NULL) {
        return enif_raise_exception(env,
            make_response(env, "error", ret_val)
        );
    }

    int result;
    session_cipher *cipher;
    session_builder *builder;
    esc_buf *response;    

    err_msg = esc_handshake_initiate(&sender_address, &recepient_address, ctx_res_p->ctx_p, &cipher, &builder, &response);
    if (err_msg != NULL) {
        return enif_raise_exception(env, make_response(env, "error", err_msg));
    }

    SIGNAL_UNREF(cipher);
    SIGNAL_UNREF(builder);

/*
    session_cipher_resource * cipher_res_p = (session_cipher_resource*) enif_alloc_resource(SESSION_CIPHER_RESOURCE, sizeof(session_cipher_resource));
    cipher_res_p->session_cipher_p = cipher;
    ERL_NIF_TERM cipher_term = enif_make_resource(env, cipher_res_p);
    //enif_release_resource(cipher_res_p);

    session_builder_resource * builder_res_p = (session_builder_resource*) enif_alloc_resource(SESSION_BUILDER_RESOURCE, sizeof(session_cipher_resource));
    builder_res_p->session_builder_p = builder;
    ERL_NIF_TERM builder_term = enif_make_resource(env, builder_res_p);
    //enif_release_resource(builder_res_p);    

*/
    ERL_NIF_TERM response_bin;
    ErlNifBinary binary;
    enif_alloc_binary(esc_buf_get_len(response), &binary);
    memcpy((char *) binary.data, (char *) esc_buf_get_data(response), esc_buf_get_len(response));    
    response_bin = enif_make_binary(env, &binary);

    esc_buf_free(response);
    //free(esc_buf_get_data(response));    

    return enif_make_tuple2(env, 
        enif_make_atom(env, "ok"),
//        cipher_term,
//        builder_term,
        response_bin
    );

    // return enif_raise_exception(env, make_response(env, "error", "not_implemented"));
};

ERL_NIF_TERM nif_esc_handshake_accept(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    context_resource *ctx_res_p = NULL;
    const char * err_msg;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_res_p)) {
        return enif_raise_exception(env, 
            make_response(env, "badarg","bad_context")
        );
    }

    signal_protocol_address sender_address;
    const char * ret_val = create_signal_protocol_address(env, argv[1], &sender_address);
    if(ret_val != NULL) {
        return enif_raise_exception(env,
            make_response(env, "badarg", ret_val)
        );
    }

    // es_log_hex("address0: ", sender_address.name, sender_address.name_len);

    ErlNifBinary handshake_bin;
    if (!enif_inspect_binary(env, argv[2], &handshake_bin)) {
        return make_response(env, "badarg", "handshake");
    }

    esc_buf *buf = esc_buf_create(handshake_bin.data, handshake_bin.size);
    session_cipher *cipher = NULL;
    session_builder *builder = NULL;  
    esc_buf *response = NULL;
    
    esc_address *address_from_p = NULL;
    err_msg = esc_handshake_accept(buf, &sender_address, ctx_res_p->ctx_p, &cipher, &builder, &address_from_p, &response);
    esc_buf_free(buf);     
    if (err_msg!=NULL) {      
        return make_response(env, "error", err_msg);
    }

    SIGNAL_UNREF(cipher);
    SIGNAL_UNREF(builder);

/*
    session_cipher_resource * cipher_res_p = (session_cipher_resource*) enif_alloc_resource(SESSION_CIPHER_RESOURCE, sizeof(session_cipher_resource));
    cipher_res_p->session_cipher_p = cipher;
    ERL_NIF_TERM cipher_term = enif_make_resource(env, cipher_res_p);
    //enif_release_resource(cipher_res_p);

    session_builder_resource * builder_res_p = (session_builder_resource*) enif_alloc_resource(SESSION_BUILDER_RESOURCE, sizeof(session_cipher_resource));
    builder_res_p->session_builder_p = builder;
    ERL_NIF_TERM builder_term = enif_make_resource(env, builder_res_p);
    //enif_release_resource(builder_res_p);    
*/
    ERL_NIF_TERM response_bin;
    ErlNifBinary binary;
    enif_alloc_binary(esc_buf_get_len(response), &binary);
    memcpy((char *) binary.data, (char *) esc_buf_get_data(response), esc_buf_get_len(response));    
    response_bin = enif_make_binary(env, &binary);

    // es_log_hex("handshake: ", (char * ) binary.data, binary.size);

    return enif_make_tuple3(env, 
        enif_make_atom(env, "ok"),
//        cipher_term,
//        builder_term,
        construct_es_address_record(env, address_from_p),
        response_bin
    );
};

ERL_NIF_TERM nif_esc_handshake_acknowledge(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    const char * err_msg;

    context_resource *ctx_res_p = NULL;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_res_p)) {
        return enif_raise_exception(env, 
            make_response(env, "badarg","bad_context")
        );
    }

    signal_protocol_address sender_address;
    const char * ret_val = create_signal_protocol_address(env, argv[1], &sender_address);
    if(ret_val != NULL) {
        return enif_raise_exception(env,
            make_response(env, "badarg", ret_val)
        );
    }    
/*
    session_builder_resource *builder_res_p = NULL;
    if (!enif_get_resource(env, argv[1], SESSION_BUILDER_RESOURCE, (void**)&builder_res_p)) {
        return enif_raise_exception(env, 
            make_response(env, "badarg","bad_session_builder")
        );
    }
*/
    ErlNifBinary handshake_bin;
    if (!enif_inspect_binary(env, argv[2], &handshake_bin)) {
        return enif_raise_exception(env,
            make_response(env, "badarg", "handshake")
        );
    }

    esc_buf *buf = esc_buf_create(handshake_bin.data, handshake_bin.size);
    session_cipher *cipher = NULL;
    esc_address *address_from_p = NULL;

    err_msg = esc_handshake_acknowledge(buf, &sender_address, ctx_res_p->ctx_p, &cipher, &address_from_p);
    esc_buf_free(buf);     
    if (err_msg!=NULL) {
        return make_response(env, "error", err_msg);
    }

    session_cipher_resource * cipher_res_p = (session_cipher_resource*) enif_alloc_resource(SESSION_CIPHER_RESOURCE, sizeof(session_cipher_resource));
    cipher_res_p->session_cipher_p = cipher;
    ERL_NIF_TERM cipher_term = enif_make_resource(env, cipher_res_p);

    ERL_NIF_TERM address_from_term = construct_es_address_record(env, address_from_p);

    return enif_make_tuple2(env,
        enif_make_atom(env, "ok"),
        address_from_term
    );
}

ERL_NIF_TERM nif_esc_encode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

    context_resource *ctx_res_p = NULL;
    const char * err_msg;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_res_p)) {
        return enif_make_badarg(env);
    }

    signal_protocol_address address;
    const char * ret_val = create_signal_protocol_address(env, argv[1], &address);
    if(ret_val != NULL) {
        return enif_raise_exception(env,
            make_response(env, "error", ret_val)
        );
    }

    ErlNifBinary buffer;
    if (!enif_inspect_binary(env, argv[2], &buffer)) {
	    return enif_make_badarg(env);
    }

    esc_buf *msg_p = signal_buffer_create(buffer.data, buffer.size);
    esc_buf *msg_encripted = NULL;

    err_msg = esc_message_encrypt_and_serialize(msg_p, &address, ctx_res_p->ctx_p, &msg_encripted);
    esc_buf_free(msg_p);

    if (err_msg != NULL ) {
        return make_response(env, "error", err_msg);
    }  

    ERL_NIF_TERM result_bin;
    ErlNifBinary binary;
    enif_alloc_binary(esc_buf_get_len(msg_encripted), &binary);
    memcpy((char *) binary.data, (char *) esc_buf_get_data(msg_encripted), esc_buf_get_len(msg_encripted));    
    
    result_bin = enif_make_binary(env, &binary);

    ERL_NIF_TERM result = enif_make_tuple2(env,
        enif_make_atom(env, "ok"),
        result_bin
    );

    esc_buf_free(msg_encripted);    

    return result;
};

ERL_NIF_TERM nif_esc_decode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    context_resource *ctx_res_p = NULL;
    const char * err_msg = NULL;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_res_p)) {
        return enif_make_badarg(env);
    }

    signal_protocol_address address;
    const char * ret_val = create_signal_protocol_address(env, argv[1], &address);
    if(ret_val != NULL) {
        return enif_raise_exception(env,
            make_response(env, "error", ret_val)
        );
    }

    ErlNifBinary buffer;
    if (!enif_inspect_binary(env, argv[2], &buffer)) {
	    return enif_make_badarg(env);
    }

    esc_buf *msg_p = signal_buffer_create(buffer.data, buffer.size);
    esc_buf *msg_decripted = NULL;

    es_log_hex("decoded: ", (char *) buffer.data, buffer.size);

    err_msg = esc_message_decrypt_from_serialized(msg_p, &address, ctx_res_p->ctx_p, &msg_decripted);
    if (err_msg) {
        return make_response(env, "error", err_msg);
    }

    ERL_NIF_TERM result_bin;
    ErlNifBinary binary;
    enif_alloc_binary(esc_buf_get_len(msg_decripted), &binary);
    memcpy((char *) binary.data, (char *) esc_buf_get_data(msg_decripted), esc_buf_get_len(msg_decripted));    
    result_bin = enif_make_binary(env, &binary);

    ERL_NIF_TERM result = enif_make_tuple2(env,
        enif_make_atom(env, "ok"),
        result_bin
    );

    esc_buf_free(msg_decripted);    

    return result;
};

ERL_NIF_TERM nif_esc_serialize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    context_resource *ctx_res_p = NULL;
    const char * err_msg;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_res_p)) {
        return enif_make_badarg(env);
    }
    esc_context *ctx_p = ctx_res_p->ctx_p;

    ERL_NIF_TERM sessions = ctx_p->session_store->serialize(env);
    ERL_NIF_TERM pre_keys = ctx_p->pre_key_store->serialize(env);
    ERL_NIF_TERM signed_pre_keys = ctx_p->signed_pre_key_store->serialize(env);
    ERL_NIF_TERM identity_keys = ctx_p->identity_key_store->serialize(env);
    ERL_NIF_TERM settings = ctx_p->settings->serialize(env);

    return enif_make_list5(env,
        enif_make_tuple2(env, enif_make_atom(env, "sessions"), sessions),
        //enif_make_tuple2(env, enif_make_atom(env, "pre_keys"), pre_keys),
        enif_make_tuple2(env, enif_make_atom(env, "pre_keys"), enif_make_atom(env, "internal")),        
        enif_make_tuple2(env, enif_make_atom(env, "signed_pre_keys"), signed_pre_keys),
        enif_make_tuple2(env, enif_make_atom(env, "identity_keys"), identity_keys),
        enif_make_tuple2(env, enif_make_atom(env, "settings"), settings)
    );
}

void esc_context_resource_destroy(ErlNifEnv* env, void* arg) {
    context_resource *ctx_res_p = (context_resource *) arg;
    esc_context_destroy_all(ctx_res_p->ctx_p);
}

void esc_session_builder_resource_destroy(ErlNifEnv* env, void* arg) {
    session_builder_resource * r = (session_builder_resource *) arg;
    session_builder_free(r->session_builder_p);
}

void esc_session_cipher_resource_destroy(ErlNifEnv* env, void* arg) {
    session_cipher_resource *r = ( session_cipher_resource * ) arg;
    session_cipher_free(r->session_cipher_p);
}

extern "C" {

    int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {

        ErlNifResourceFlags flags = (ErlNifResourceFlags) (ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);
        CONTEXT_RESOURCE = NULL;
        CONTEXT_RESOURCE = enif_open_resource_type(env, NULL, "esc_context_resource", &esc_context_resource_destroy, flags, NULL);
        if (CONTEXT_RESOURCE == NULL) {
            return -1;
        }

        SESSION_BUILDER_RESOURCE = NULL;
        SESSION_BUILDER_RESOURCE = enif_open_resource_type(env, NULL, "esc_session_builder_resource", &esc_session_builder_resource_destroy, flags, NULL);    
        if (SESSION_BUILDER_RESOURCE == NULL) {
            return -2;
        }

        SESSION_CIPHER_RESOURCE = NULL;
        SESSION_CIPHER_RESOURCE = enif_open_resource_type(env, NULL, "esc_session_cipher_resource", &esc_session_cipher_resource_destroy, flags, NULL);    
        if (SESSION_BUILDER_RESOURCE == NULL) {
            return -3;
        }
        return 0;        
    }
  
	int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info);

    static ErlNifFunc nif_funcs[] = {
            {"new", 0, nif_esc_new},
            {"generate_identity_keys", 1, nif_esc_generate_identity_keys},
            {"is_session_exists_initiated", 2, nif_esc_is_session_exists_initiated },
            {"handshake_initiate", 3, nif_esc_handshake_initiate },
            {"handshake_accept", 3, nif_esc_handshake_accept },
            {"handshake_acknowledge", 3, nif_esc_handshake_acknowledge },
            {"encode", 3, nif_esc_encode },
            {"decode", 3, nif_esc_decode },
            {"serialize", 1, nif_esc_serialize}
    };

    ERL_NIF_INIT(erl_signal_nif, nif_funcs, &on_load, NULL, NULL, NULL);
};