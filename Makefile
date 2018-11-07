all: compile

compile:
	./rebar3 compile

run:
	./rebar3 shell

.PHONY: test
test:
	./rebar3 ct

.PHONY: clean
clean:
	./rebar3 clean

