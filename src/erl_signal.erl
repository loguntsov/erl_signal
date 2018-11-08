-module(erl_signal).

-include("erl_signal.hrl").

-export([
    new/0,
    generate_identity_keys/1,
    is_session_exists_initiated/2, 
    handshake_initiate/2,
    handshake_accept/3,
    handshake_acknowledge/3,
    encode/3, decode/3
]).

new() ->
    erl_signal_nif:new().

generate_identity_keys(Session) ->
    erl_signal_nif:generate_identity_keys(Session).

is_session_exists_initiated(Session, MyAddress) when ?IS_ES_ADDRESS(MyAddress) ->
    erl_signal_nif:is_session_exists_initiated(Session, MyAddress).

handshake_initiate(Session, ToAddress) when ?IS_ES_ADDRESS(ToAddress) ->
    erl_signal_nif:handshake_initiate(Session, ToAddress).


handshake_accept(Session, FromAddress, Handshake) when  ?IS_ES_ADDRESS(FromAddress), is_binary(Handshake) ->
    erl_signal_nif:handshake_accept(Session, FromAddress, Handshake).

handshake_acknowledge(Session, MyHandshake, AcceptedHandshake) when  ?IS_ES_HANDSHAKE(MyHandshake), is_binary(AcceptedHandshake) ->
    erl_signal_nif:handshake_acknowledge(Session, MyHandshake, AcceptedHandshake).

encode(Session, ToAddress, Binary) when ?IS_ES_ADDRESS(ToAddress), is_binary(Binary) ->
    erl_signal_nif:encode(Session, ToAddress, Binary).

decode(Session, FromAddress, Binary) when ?IS_ES_ADDRESS(FromAddress), is_binary(Binary) ->
    erl_signal_nif:decode(Session, FromAddress, Binary).
