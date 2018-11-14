-record(es_address, {
    name :: binary(),
    device_id :: integer()
}).

-define(IS_ES_ADDRESS(X), is_record(X, es_address)).


