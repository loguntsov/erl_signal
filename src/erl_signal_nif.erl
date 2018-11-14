-module(erl_signal_nif).

-export([
    new/0,
    generate_identity_keys/1,
    is_session_exists_initiated/2, 
    handshake_initiate/3,
    handshake_accept/3,
    handshake_acknowledge/3,
    encode/3, decode/3,
    serialize/1
]).

-on_load(init/0).

-include("erl_signal.hrl").

-type address() :: #es_address{}.
-type session() :: reference() | binary(). %% Depends from version of Erlang
-type session_builder() :: reference() | binary(). %% Depends from version of Erlang
-type session_cipher() :: reference() | binary(). %% Depends from version of Erlang

-export_type([
    address/0, session/0, session_builder/0, session_cipher/0
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

-spec handshake_initiate(session(), address(), address()) -> { ok, session_cipher(), session_builder(), Response :: binary() } | { error, Reason :: atom() }.
handshake_initiate(_Session, _FromAddress, _ToAddress) ->
    erlang:nif_error({error, not_loaded}).

-spec handshake_accept(session(), address(), binary()) -> { ok, session_cipher(), session_builder(), Response :: binary() } | { error, Reason :: atom() }.
handshake_accept(_Session, _FromAddress, _Handshake) ->
    erlang:nif_error({error, not_loaded}).

-spec handshake_acknowledge(session(), session_builder(), binary()) -> {ok, From :: address() } | { error, Reason :: atom() }.
handshake_acknowledge(_Session, _SessionAddress, _Binary) ->
    erlang:nif_error({error, not_loaded}).

-spec encode(session(), address(), binary()) -> { ok, binary()} | { error, Reason :: atom() }.
encode(_Session, _ToAddress, _Binary) ->
    erlang:nif_error({error, not_loaded}).

-spec decode(session(), address(), binary()) -> {ok, binary()} | { error, Reason :: atom() }.
decode(_Session, _FromAddress, _Binary) ->
    erlang:nif_error({error, not_loaded}).

serialize(_Session) ->
    erlang:nif_error({error, not_loaded}).
   
