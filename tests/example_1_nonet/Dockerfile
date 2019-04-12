from ubuntu:latest
copy example_1_nonet.bin /
copy libc.so.6 /
copy ld-linux-x86-64.so.2 /

entrypoint [ "/ld-linux-x86-64.so.2", "--library-path", "/", "/example_1_nonet.bin", "secret_of_life", "supersecretpassword" ]
#entrypoint ["/example_1_nonet.bin", "secret_of_life", "supersecretpassword" ]
