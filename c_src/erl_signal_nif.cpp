#include <erl_nif.h>
#include <cstring>
#include <iostream>

#include "libsignal-c/signal_protocol.h"
#include "libsignal-c/session_builder.h"

#include "erl_signal_client.h"
#include "erl_signal_client_storage.h"

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
        return "deviceid_is_not_integer";
    }

    result->name = (char *) buffer.data;
    result->name_len = buffer.size;
    result->device_id = device_id;

    return NULL;
}

int create_handshake(ErlNifEnv* env, const ERL_NIF_TERM es_handshake, esc_handshake **handshake) {
    
    int arity; 
    const ERL_NIF_TERM *array = NULL; 

    if(enif_get_tuple(env, es_handshake, &arity, &array) != 3) { \
        return -1;
    }    
    
    session_builder_resource *builder;

    if (!enif_get_resource(env, array[1], SESSION_BUILDER_RESOURCE, (void**)&builder)) {
        return -1;
    }

    ErlNifBinary buffer;
    if (!enif_inspect_binary(env, array[2], &buffer)) {
	    return -2;
    }

    esc_handshake *h = new esc_handshake();
    h->session_builder_p = builder->session_builder_p;
    h->handshake_msg_p = signal_buffer_create(buffer.data, buffer.size);

    *handshake = h;

    return 0;
}

void destroy_handshake(esc_handshake *handshake) {
    signal_buffer_free(handshake->handshake_msg_p);
    delete handshake;
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

/*
    {
        esc_storage k;
        esc_storage::row row;
        row.store(std::string("column"), std::string("asd")),
        k.set(std::string("test"), row);
        k.clear();
    }
*/
//*
    err_msg = esc_generate_identity_keys(ctx_res_p->ctx_p);
    if (err_msg != NULL) {
        return enif_raise_exception(env, make_response(env, "badarg", err_msg));
    }
//*/   
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


    return enif_raise_exception(env, make_response(env, "error", "not_implemented"));
};

ERL_NIF_TERM nif_esc_handshake_accept(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {


    return enif_raise_exception(env, make_response(env, "error", "not_implemented"));
};

ERL_NIF_TERM nif_esc_handshake_acknowledge(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

    /* Process the pre key bundles */
//    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle);


    return enif_raise_exception(env, make_response(env, "error", "not_implemented"));
};

ERL_NIF_TERM nif_esc_encode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

    context_resource *ctx_res_p = NULL;
    const char * err_msg;
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

    ErlNifBinary buffer;
    if (!enif_inspect_binary(env, argv[2], &buffer)) {
	    return enif_make_badarg(env);
    }

    esc_buf *msg_p = signal_buffer_create(buffer.data, buffer.size);
    esc_buf *msg_encripted = NULL;

    err_msg = esc_message_encrypt_and_serialize(msg_p, address, ctx_res_p->ctx_p, &msg_encripted);

    if (err_msg != NULL ) {
        return make_response(env, "error", err_msg);
    }

    ErlNifBinary result_bin;
    result_bin.data = (unsigned char*) esc_buf_get_data(msg_encripted);
    result_bin.size = esc_buf_get_len(msg_encripted);
    ERL_NIF_TERM result = enif_make_tuple(env,
        enif_make_atom(env, "ok"),
        enif_make_binary(env, &result_bin)
    );

    esc_buf_free(msg_p);
    esc_buf_free(msg_encripted);    

    return result;
};

ERL_NIF_TERM nif_esc_decode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return enif_raise_exception(env, make_response(env, "error", "not_implemented"));
};


void esc_context_resource_destroy(ErlNifEnv* env, void* arg) {
    context_resource *ctx_res_p = (context_resource *) arg;
    SIGNAL_UNREF(ctx_res_p->ctx_p);
}

void esc_session_builder_resource_destroy(ErlNifEnv* env, void* arg) {
    session_builder_resource * r = (session_builder_resource *) arg;
    SIGNAL_UNREF(r->session_builder_p);
}

void esc_session_cipher_resource_destroy(ErlNifEnv* env, void* arg) {
    session_cipher_resource *r = ( session_cipher_resource * ) arg;
    SIGNAL_UNREF(r->session_cipher_p);
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
//            {"handshake_initiate", 2, nif_esc_handshake_initiate },
//            {"handshake_accept", 3, nif_esc_handshake_accept },
//            {"handshake_acknowledge", 3, nif_esc_handshake_acknowledge },
            {"encode", 3, nif_esc_encode },
            {"decode", 3, nif_esc_decode }            
    };

    ERL_NIF_INIT(erl_signal_nif, nif_funcs, &on_load, NULL, NULL, NULL);
};