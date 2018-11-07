#include <erl_nif.h>
#include <cstring>
#include <iostream>

#include "libsignal-c/signal_protocol.h"
#include "libsignal-c/session_builder.h"

#include "erl_signal_client.h"

typedef struct {
    session_builder* session_builder_p = NULL;
} session_builder_resource;


static ErlNifResourceType* CONTEXT_RESOURCE;
static ErlNifResourceType* SESSION_BUILDER_RESOURCE;    

int create_signal_protocol_address(ErlNifEnv* env, const ERL_NIF_TERM es_address, signal_protocol_address *result) {
    int arity; 
    const ERL_NIF_TERM *array = NULL; 

    if(enif_get_tuple(env, es_address, &arity, &array) != 3) { \
        return -1;
    }

    ErlNifBinary buffer;
    if (!enif_inspect_binary(env, array[1], &buffer)) {
	    return -2;
    }
       
    unsigned int device_id;

    if (!enif_get_uint(env, array[2], &device_id)) {
        return -3;
    }

    result->name = (char *) buffer.data;
    result->name_len = buffer.size;
    result->device_id = device_id;

    return 0;
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

    esc_context *ctx_p = (esc_context*) enif_alloc_resource(CONTEXT_RESOURCE, sizeof(esc_context));
    
    int a = esc_context_create(&ctx_p);
    if (a != 0 ) {
        return enif_make_tuple2(env,
            enif_make_atom(env, "error"),
            enif_make_atom(env, "cant_create_context")
        );
    }
    a = esc_init(ctx_p);
    if (a != 0) {
        return enif_make_tuple2(env,
            enif_make_atom(env, "error"),
            enif_make_atom(env, "cant_init_context")
        );
    }
	ERL_NIF_TERM result = enif_make_resource(env, ctx_p);
	return enif_make_tuple2(env, enif_make_atom(env, "ok"), result);
}

ERL_NIF_TERM nif_esc_generate_identity_keys(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    
    esc_context *ctx_p = NULL;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_p)) {
        return enif_make_badarg(env);
    }

    if (!esc_generate_identity_keys(ctx_p)) {
        return enif_make_badarg(env);
    }

    return enif_make_atom(env, "ok");
}

ERL_NIF_TERM nif_esc_is_session_exists_initiated(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
   
    esc_context *ctx_p = NULL;
    if (!enif_get_resource(env, argv[0], CONTEXT_RESOURCE, (void**)&ctx_p)) {
        return enif_make_badarg(env);
    }

    signal_protocol_address *address = new signal_protocol_address();
    

    if(!create_signal_protocol_address(env, argv[1], address)) {
        return enif_make_badarg(env);
    }
    
    int r = esc_session_exists_initiated(address, ctx_p);

    if (r==0) return enif_make_atom(env, "false");
    if (r==1) return enif_make_atom(env, "true");
    
    return enif_make_badarg(env);
}

ERL_NIF_TERM nif_esc_handshake_initiate(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return enif_make_atom(env, "not_implemented");
};

ERL_NIF_TERM nif_esc_handshake_accept(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return enif_make_atom(env, "not_implemented");
};

ERL_NIF_TERM nif_esc_handshake_acknowledge(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return enif_make_atom(env, "not_implemented");
};

ERL_NIF_TERM nif_esc_encode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return enif_make_atom(env, "not_implemented");
};

ERL_NIF_TERM nif_esc_decode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    return enif_make_atom(env, "not_implemented");
};




void esc_context_resource_destroy(ErlNifEnv* env, void* arg) {
    esc_cleanup((esc_context * ) arg);
}

void esc_session_builder_resource_destroy(ErlNifEnv* env, void* arg) {
    session_builder_free(((session_builder_resource *) arg)->session_builder_p);
    delete (session_builder_resource *) arg;
}

extern "C" {

    int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {

        ErlNifResourceFlags flags = (ErlNifResourceFlags) (ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);
        CONTEXT_RESOURCE = enif_open_resource_type(env, NULL, "esc_context_resource", esc_context_resource_destroy, flags, 0);
        SESSION_BUILDER_RESOURCE = enif_open_resource_type(env, NULL, "esc_session_builder_resource", esc_session_builder_resource_destroy, flags, 0);    
        return 0;
    }


    ERL_NIF_TERM tera_new_protocol(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    ERL_NIF_TERM tera_encode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    
	int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info);

    static ErlNifFunc nif_funcs[] = {
            {"new", 0, nif_esc_new},
            {"generate_identity_keys", 1, nif_esc_generate_identity_keys},
            {"is_session_exists_initiated", 2, nif_esc_is_session_exists_initiated },
            {"handshake_initiate", 2, nif_esc_handshake_initiate },
            {"handshake_accept", 3, nif_esc_handshake_accept },
            {"handshake_acknowledge", 3, nif_esc_handshake_acknowledge },
            {"encode", 3, nif_esc_encode },
            {"decode", 3, nif_esc_decode }            
    };

    ERL_NIF_INIT(erl_signal_nif, nif_funcs, &on_load, NULL, NULL, NULL);
};