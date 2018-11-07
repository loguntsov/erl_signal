-module(erl_signal_nif).

-export([
    new/0,
    generate_identity_keys/1,
    is_session_exists_initiated/2, 
    handshake_initiate/2,
    handshake_accept/3,
    handshake_acknowledge/3,
    encode/3, decode/3
]).

-on_load(init/0).

-include("erl_signal.hrl").

-type address() :: #es_address{}.
-type handshake() :: #es_handshake{}.
-type session() :: reference().
-export_type([
    address/0, session/0, handshake/0
]).

init() ->
    SoName = case code:priv_dir(erl_signal) of
        {error, bad_name} ->
            case code:which(?MODULE) of
                Filename when is_list(Filename) ->
                    filename:join([filename:dirname(Filename),"../priv", "erl_signal_nif"]);
                _ ->
                    filename:join("../priv", "erl_signal_nif")
            end;
        Dir ->
            filename:join(Dir, "erl_signal_nif")
    end,
    erlang:load_nif(SoName, 0).

-spec new() -> { ok, Session :: session() }.
new() ->
    erlang:nif_error({error, not_loaded}).

-spec generate_identity_keys(session()) -> ok.
generate_identity_keys(_Session) ->
    erlang:nif_error({error, not_loaded}).    

-spec is_session_exists_initiated(session(), address()) -> boolean().
is_session_exists_initiated(_Session, _MyAddress) -> 
    erlang:nif_error({error, not_loaded}).

-spec handshake_initiate(session(), address()) -> { ok, handshake() } | { error, Reason :: atom() }.
handshake_initiate(_Session, _ToAddress) -> 
    erlang:nif_error({error, not_loaded}).    

-spec handshake_accept(session(), address(), binary()) -> { ok, handshake() } | { error, Reason :: atom() }.
handshake_accept(_Session, _FromAddress, _Handshake) -> 
    erlang:nif_error({error, not_loaded}).

-spec handshake_acknowledge(session(), handshake(), binary()) -> ok | { error, Reason :: atom() }.
handshake_acknowledge(_Session, _MyHandshake, _AcceptedHandshake) -> 
    erlang:nif_error({error, not_loaded}).

-spec encode(session(), address(), binary()) -> { ok, binary()} | { error, Reason :: atom() }.
encode(_Session, _ToAddress, _Binary) ->
    erlang:nif_error({error, not_loaded}).

-spec decode(session(), address(), binary()) -> {ok, binary()} | { error, Reason :: atom() }.
decode(_Session, _FromAddress, _Binary) -> 
    erlang:nif_error({error, not_loaded}).
   
