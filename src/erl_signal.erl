-module(erl_signal).

-export([
    new/1,
    encode/2
]).

-on_load(init/0).

-callback init() -> ok.
-callback session_store

init() ->
    SoName = case code:priv_dir(erl_signal) of
        {error, bad_name} ->
            case code:which(?MODULE) of
                Filename when is_list(Filename) ->
                    filename:join([filename:dirname(Filename),"../priv", "erl_signal"]);
                _ ->
                    filename:join("../priv", "erl_signal")
            end;
        Dir ->
            filename:join(Dir, "erl_signal")
    end,
    erlang:load_nif(SoName, 0).

-spec new(Key :: binary()) -> { ok, Object :: reference() }.
new(_Key) ->
    erlang:nif_error({error, not_loaded}).

-spec encode(Object :: reference(), Buffer :: binary()) -> NewBuffer :: binary().
encode(_Ref, _Binary) ->
    erlang:nif_error({error, not_loaded}).