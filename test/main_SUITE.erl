-module(main_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-include("erl_signal.hrl").

%% API
-compile(export_all).

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(erl_signal),
    Config.

end_per_suite(Config) ->
    application:stop(erl_signal),
    Config.

init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_TestCaseName, _Config) ->
    _Config.

all() -> [
    main_test
].

main_test(_) ->
    { ok, Alice } = erl_signal:new(),
    %% error_logger:info_msg("hello ~p", [ Alice ]),
    ok = erl_signal:generate_identity_keys(Alice),
    AliceAddress = #es_address{
        name = <<"alice">>,
        device_id = 1
    },

    { ok, Bob } = erl_signal:new(),
    ok = erl_signal:generate_identity_keys(Bob),
    BobAddress = #es_address{
       name = <<"bob">>,
        device_id = 1
    },

    false = (catch erl_signal:is_session_exists_initiated(Alice, BobAddress)),
    false = erl_signal:is_session_exists_initiated(Bob, AliceAddress),

    %ok = erl_signal:create_session(Alice, BobAddress),
    %ok = erl_signal:create_session(Bob, AliceAddress),

%    { ok, AliceHandshake } = erl_signal:handshake_initiate(Alice, BobAddress),
%    { ok, BobHandshake } = erl_signal:handshake_accept(Bob, AliceAddress, AliceHandshake#es_handshake.handshake),
%    ok = erl_signal:handshake_acknowledge(Alice, AliceHandshake, BobHandshake#es_handshake.handshake),
%%
%%    true = erl_signal:is_session_exists_initiated(Alice, BobAddress),
%%    true = erl_signal:is_session_exists_initiated(Bob, AliceAddress),
%%
      { ok, EncryptedHello1 } = erl_signal:encode(Alice, BobAddress, <<"hello from Alice">>),
%%    { ok, <<"hello from Alice">>} = erl_signal:decode(Bob, AliceAddress, EncryptedHello1),
%%
%%    { ok, EncryptedHello2 } = erl_signal:encode(Bob, AliceAddress, <<"hello from Bob">>),
%%    { ok, <<"hello from Bob">>} = erl_signal:decode(Alice, BobAddress, EncryptedHello2),

    ok.

    
