% This doesn't cause false positives yet, but with
% more research we may be able to. Erlang is supposed
% to have lightweight threads called "processes"
% created by the `spawn` keyword, but I do not know
% Erlang well enough to understand how this interfaces
% with threads at the kernel level for the purposes of
% detecting stack pivots.
%
% This can be run by installing erlang (`apt install erlang`)
% opening an erlang shell with `erl`, then compiling/running
% the module with `c(erlang_process).` then `erlang_process:start().`
% You can leave the Erlang shell with `init:stop().`

-module(erlang_process).
-export([start/0, call/2, for/2]).

for(0,_) ->
   [];

   for(N,Term) when N > 0 ->
   Pid = spawn(?MODULE, call, ["hello", "forloop"]),
   io:fwrite("~p",[Pid]),
   [Term|for(N-1,Term)].

call(Arg1, Arg2) ->
   io:format("~p ~p~n", [Arg1, Arg2]).

start() ->
   Pid = spawn(?MODULE, call, ["hello", "process"]),
   io:fwrite("~p",[Pid]),

   for(5, 1).
