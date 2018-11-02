#include <erl_nif.h>
#include <cstring>
#include <iostream>

#include "libsignal-c/signal_protocol.h"

#include "erl_signal.hpp"

typedef struct {
    TeraCrypto* protocol;
} tera_handle;

extern "C" {

    static signal_context* GLOBAL_CONTEXT;

    // static ErlNifResourceType* TERA_CRYPTO_RESOURCE;

    ERL_NIF_TERM tera_new_protocol(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    ERL_NIF_TERM tera_encode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
    
    void tera_protocol_destroy(ErlNifEnv* env, void* arg);
	int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info);

    static ErlNifFunc nif_funcs[] = {
            {"new",           1, tera_new_protocol},
            {"encode",        2, tera_encode}
    };

    ERL_NIF_INIT(tera_crypto, nif_funcs, &on_load, NULL, NULL, NULL);
};

ERL_NIF_TERM tera_new_protocol(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary str;

    if (!enif_inspect_binary(env, argv[0], &str)) {
	    return enif_make_badarg(env);
    }

    if (str.size != 680) {
      return enif_make_badarg(env);
    }

		tera_handle* handle = (tera_handle*) enif_alloc_resource(TERA_CRYPTO_RESOURCE, sizeof(tera_handle));
		handle->protocol = new TeraCrypto((unsigned int *) str.data);
		ERL_NIF_TERM result = enif_make_resource(env, handle);
		enif_release_resource(handle);
		return enif_make_tuple2(env, enif_make_atom(env, "ok"), result);
}

ERL_NIF_TERM tera_encode(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary buffer;
    tera_handle* handle;

    if (!enif_get_resource(env, argv[0], TERA_CRYPTO_RESOURCE, (void**)&handle)) {
      return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[1], &buffer)) {
	    return enif_make_badarg(env);
    }

    ERL_NIF_TERM result;
    unsigned char * q = enif_make_new_binary(env, buffer.size, &result);
    memcpy(q, buffer.data, buffer.size);

    handle->protocol->apply(q, buffer.size);

    return result;
}

void signal_global_context_destroy(ErlNifEnv* env, void* arg) {
    delete (signal_context*) arg;
}

int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {

    result = signal_context_create(&global_context, 0);



    ErlNifResourceFlags flags = (ErlNifResourceFlags) (ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);
    GLOBAL_CONTEXT = enif_open_resource_type(env, NULL, "global_context", &signal_global_context_destroy, flags, 0);
    return 0;
}
