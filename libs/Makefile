all: libsignal-protocol-c/.compiled cJSON/.compiled


libsignal-protocol-c/.compiled:
	git clone https://github.com/signalapp/libsignal-protocol-c.git \
	    && cd libsignal-protocol-c \
	    && git checkout v2.3.2 \
	    && mkdir build \
	    && cd build \
	    && cmake -DCMAKE_BUILD_TYPE=Debug .. \
	    && make \
	    && touch ../.compiled

cJSON/.compiled:
	git clone https://github.com/DaveGamble/cJSON.git \
	    && cd cJSON \
	    && make \
	    && touch .compiled

