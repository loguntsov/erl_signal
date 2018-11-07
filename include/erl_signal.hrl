-record(es_address, {
    name :: binary(),
    device_id :: integer()
}).

-define(IS_ES_ADDRESS(X), is_record(X, es_address)).

-record(es_handshake, {
    session_builder :: reference(),
    handshake :: binary()
}).

-define(IS_ES_HANDSHAKE(X), is_record(X, es_handshake)).

