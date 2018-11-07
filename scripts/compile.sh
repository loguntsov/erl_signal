#!/bin/bash
make -C ./libs
make -C ./c_src -j 5
