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

    { ok, AliceCipher, AliceSessionBuilder, AliceHandshake } = erl_signal_nif:handshake_initiate(Alice, AliceAddress, BobAddress),
    true = is_binary(AliceHandshake),

    { ok, BobCipher, BobSessionBuilder, AliceAddress, BobHandshake } = erl_signal_nif:handshake_accept(Bob, BobAddress, AliceHandshake),

    true = (BobHandshake /= AliceHandshake),
    true = is_binary(BobHandshake),

    true = erl_signal_nif:is_session_exists_initiated(Bob, AliceAddress),

    { ok, BobAddress } = erl_signal_nif:handshake_acknowledge(Alice, AliceAddress, BobHandshake),
    % [] = erl_signal_nif:serialize(Alice),

    true = erl_signal_nif:is_session_exists_initiated(Alice, BobAddress),

    Bin = <<"asdfkfjskldfjklsfjklsdjfkljsdklfjklsdjfkldasjflkjasdfhjasdhfkjashfkjhaskjhfkjasdhfkjashfkjvnxc,mnv,mxczn,mvn,mnsfjhjshfkjshgfuwryhtouy4o85y8275oiqwjgfiheoulholasrhvgoaehglaigliehaogihadglhdlgh,dhfgrhewotguhgljhd,nbvg,mxnb,mxcnbvjhdlushgoueyhrtghngb,.nb,mn,mxcvnbjchdfkljuhglhsg;fjsd;fj;asdfjksajfkljgldhfgkjhdfkjghorueyhtghgljdhfgljdfkgj;ksagfj;asfkj;sjfkljasdfjh">>,
    { ok, EncryptedHello1 } = erl_signal_nif:encode(Alice, BobAddress, Bin),
    true = (size(EncryptedHello1) >= size(Bin)),
    Len = size(EncryptedHello1)-0,

    { ok, Bin } = erl_signal_nif:decode(Alice, BobAddress, <<EncryptedHello1:Len/binary>>),
%%
%%    { ok, EncryptedHello2 } = erl_signal_nif:encode(Bob, AliceAddress, <<"hello from Bob">>),
%%    { ok, <<"hello from Bob">>} = erl_signal_nif:decode(Alice, BobAddress, EncryptedHello2),

    ok.

    
