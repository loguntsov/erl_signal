all: compile

compile:
	./rebar3 compile

run:
	./rebar3 shell

.PHONY: test
test:
	rm -rf test/ct_logs
	./rebar3 ct

.PHONY: clean
clean:
	rm -rf test/ct_logs
	./rebar3 clean

