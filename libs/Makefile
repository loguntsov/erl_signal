all: libsignal-protocol-c/.compiled cJSON/.compiled


libsignal-protocol-c/.get:
	git clone https://github.com/signalapp/libsignal-protocol-c.git \
	    && cd libsignal-protocol-c \
	    && git checkout v2.3.2 \
	    && sed -n -i 'p;41a  SET(CMAKE_C_FLAGS "\x24\{CMAKE_C_FLAGS} -fPIC")' CMakeLists.txt \
	    && touch .get

libsignal-protocol-c/.compiled: libsignal-protocol-c/.get
	cd libsignal-protocol-c \
	    && mkdir -p build \
	    && cd build \
	    && cmake -DCMAKE_BUILD_TYPE=Debug .. \
	    && make \
	    && touch ../.compiled

cJSON/.get:
	git clone https://github.com/DaveGamble/cJSON.git \
	    && touch cJSON/.get

cJSON/.compiled: cJSON/.get
	cd cJSON \
	    && make \
	    && touch .compiled

