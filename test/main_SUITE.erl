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
    main_test,
    bad_handshake_accept_test,
    initiate_without_acknowledge
].

main_test(_) ->
    { ok, Alice } = erl_signal_nif:new(),
    ok = erl_signal_nif:generate_identity_keys(Alice),
    AliceAddress = #es_address{
        name = <<"alice">>,
        device_id = 5
    },

    { ok, Bob } = erl_signal_nif:new(),
    ok = erl_signal_nif:generate_identity_keys(Bob),
    BobAddress = #es_address{
       name = <<"bob">>,
       device_id = 2
    },

    false = erl_signal_nif:is_session_exists_initiated(Alice, BobAddress),
    false = erl_signal_nif:is_session_exists_initiated(Bob, AliceAddress),

    { ok, AliceHandshake } = erl_signal_nif:handshake_initiate(Alice, AliceAddress, BobAddress),
    true = is_binary(AliceHandshake),

    { ok, AliceAddress, BobHandshake } = erl_signal_nif:handshake_accept(Bob, BobAddress, binary:copy(AliceHandshake)),

    true = (BobHandshake /= AliceHandshake),
    true = is_binary(BobHandshake),

    true = erl_signal_nif:is_session_exists_initiated(Bob, AliceAddress),

    { ok, BobAddress } = erl_signal_nif:handshake_acknowledge(Alice, AliceAddress, BobHandshake),
    true = erl_signal_nif:is_session_exists_initiated(Alice, BobAddress),

    Bin2 = <<"Hello from Bob">>,
    { ok, EncryptedHello2 } = erl_signal_nif:encode(Bob, AliceAddress, Bin2),
    { ok, Bin2} = erl_signal_nif:decode(Alice, BobAddress, EncryptedHello2),

    Bin1 = <<"Hello from Bob with love">>,
    { ok, EncryptedHello3 } = erl_signal_nif:encode(Bob, AliceAddress, Bin1),
    { ok, Bin1} = erl_signal_nif:decode(Alice, BobAddress, EncryptedHello3),

    Bin3 = <<"Hello from Alice with love">>,
    { ok, EncryptedHello1 } = erl_signal_nif:encode(Alice, BobAddress, Bin3),
    { ok, Bin3 } = erl_signal_nif:decode(Bob, AliceAddress,  EncryptedHello1 ),

    ok.

bad_handshake_accept_test(_) ->
    { ok, Alice } = erl_signal_nif:new(),
    ok = erl_signal_nif:generate_identity_keys(Alice),
    AliceAddress = #es_address{
        name = <<"alice">>,
        device_id = 5
    },

    {error,bad_handshake} = erl_signal_nif:handshake_accept(Alice, AliceAddress, <<"this is bad handshake">>),
    {error,bad_handshake} = erl_signal_nif:handshake_accept(Alice, AliceAddress, <<"">>),

    ok.

initiate_without_acknowledge(_) ->
    { ok, Alice } = erl_signal_nif:new(),
    ok = erl_signal_nif:generate_identity_keys(Alice),
    AliceAddress = #es_address{
        name = <<"alice">>,
        device_id = 5
    },

    { ok, Bob } = erl_signal_nif:new(),
    ok = erl_signal_nif:generate_identity_keys(Bob),
    BobAddress = #es_address{
       name = <<"bob">>,
       device_id = 2
    },

    { ok, AliceHandshake } = erl_signal_nif:handshake_initiate(Alice, AliceAddress, BobAddress),
    { ok, AliceAddress, _BobHandshake } = erl_signal_nif:handshake_accept(Bob, BobAddress, binary:copy(AliceHandshake)),

    true = erl_signal_nif:is_session_exists_initiated(Bob, AliceAddress),

    Bin2 = <<"Hello from Bob">>,
    { ok, EncryptedHello2 } = erl_signal_nif:encode(Bob, AliceAddress, Bin2),
    { ok, Bin2 } = erl_signal_nif:decode(Alice, BobAddress, EncryptedHello2),

    true = erl_signal_nif:is_session_exists_initiated(Alice, BobAddress),

    true = erl_signal_nif:is_session_exists_initiated(Alice, BobAddress),

    ok.

