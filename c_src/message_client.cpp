#include <ctype.h> // toupper
#include <stdio.h> // printf, getline
#include <stdlib.h> // exit codes
#include <sys/types.h> // socket
#include <sys/socket.h> // socket
#include <netdb.h> // getaddrinfo
#include <string.h> // memset, strlen
#include <unistd.h> // write

// #include "axolotl.h"

#include "erl_signal_client.h"

#define PORT "5555"

int main(void) {
  printf("sup\n");
  printf("initializing context for alice...\n");
  esc_context * ctx_a_p;
  if (esc_context_create(&ctx_a_p)) {
    fprintf(stderr, "failed to create axc context\n");
    return EXIT_FAILURE;
  }

  esc_context_set_log_func(ctx_a_p, esc_default_log);
  esc_context_set_log_level(ctx_a_p, ESC_LOG_DEBUG);

  printf("set db fn\n");

  if (esc_init(ctx_a_p)) {
    fprintf(stderr, "failed to init axc\n");
    return EXIT_FAILURE;
  }

  printf("installing client for alice...\n");
  if (esc_install(ctx_a_p)) {
    fprintf(stderr, "failed to install axc\n");
    esc_cleanup(ctx_a_p);
    return EXIT_FAILURE;
  }

  printf("initializing context for bob...\n");
  esc_context * ctx_b_p;
  if (esc_context_create(&ctx_b_p)) {
    fprintf(stderr, "failed to create axc context\n");
    return EXIT_FAILURE;
  }

  esc_context_set_log_func(ctx_b_p, esc_default_log);
  esc_context_set_log_level(ctx_b_p, ESC_LOG_DEBUG);

  if (esc_init(ctx_b_p)) {
    fprintf(stderr, "failed to init axc\n");
    return EXIT_FAILURE;
  }

  printf("installing client for bob...\n");
  if (esc_install(ctx_b_p)) {
    fprintf(stderr, "failed to install axc\n");
    esc_cleanup(ctx_b_p);
    return EXIT_FAILURE;
  }

  esc_address addr_a = {
      .name = "alice",
      .name_len = 5,
      .device_id = 1
  };

  esc_address addr_b = {
      .name = "bob",
      .name_len = 3,
      .device_id = 1
  };

  printf("checking if session already exists\n");
  if (!esc_session_exists_initiated(&addr_b, ctx_a_p)) {
    printf("creating session between alice and bob\n");
    printf("creating handshake initiation message\n");
    esc_handshake * handshake_a;
    if (esc_handshake_initiate(&addr_b, ctx_a_p, &handshake_a)) {
      fprintf(stderr, "failed to initialize handshake from alice to bob\n");
      esc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    printf("'sending' the message to bob and accepting it\n");
    esc_handshake * handshake_b;
    if (esc_handshake_accept(esc_handshake_get_data(handshake_a), &addr_a, ctx_b_p, &handshake_b)) {
      fprintf(stderr, "failed to accept handshake on bob's side\n");
      esc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    printf("'sending' response from bob back to alice\n");
    if (esc_handshake_acknowledge(esc_handshake_get_data(handshake_b), handshake_a, ctx_a_p)) {
      fprintf(stderr, "failed to acknowledge handhshake on alice' side\n");
      esc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    printf("session created on each side\n");
  } else {
    printf("session exists.\n");
  }
  printf("now trying to ready to 'send' and 'receive' messages\n");

  char * line = NULL;
  size_t len = 0;
  printf("enter message: ");
  //goto cleanup;
  while(getline(&line, &len, stdin)) {
    esc_buf * ciphertext_p;
    esc_buf * msg_p = esc_buf_create((uint8_t *) line, strlen(line) + 1);
    if (esc_message_encrypt_and_serialize(msg_p, &addr_b, ctx_a_p, &ciphertext_p)) {
      fprintf(stderr, "failed to encrypt message from alice to bob\n");
      esc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    printf("encrypted message from alice to bob: %s\n", line);

    char * buf = (char * ) esc_buf_get_data(ciphertext_p);

    printf("ciphertext:\n");
    for (size_t i = 0; i < esc_buf_get_len(ciphertext_p); i++) {
      printf("0x%02X ", buf[i]);
    }
    printf("\n");

    esc_buf * plaintext_p;
    if (esc_message_decrypt_from_serialized(ciphertext_p, &addr_a, ctx_b_p, &plaintext_p)) {
      fprintf(stderr, "failed to decrypt message from alice to bob\n");
      esc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    printf("decrypted message: %s\n", esc_buf_get_data(plaintext_p));

    char * upper = (char * ) esc_buf_get_data(plaintext_p);
    for (size_t i = 0; i < strlen(upper); i++) {
      upper[i] = toupper(upper[i]);
    }
    printf("bob sending reply...\n");

    esc_buf * upper_buf = esc_buf_create((uint8_t *) upper, strlen(upper) + 1);

    if (esc_message_encrypt_and_serialize(upper_buf, &addr_a, ctx_b_p, &ciphertext_p)) {
      fprintf(stderr, "failed to encrypt message from bob to alice\n");
      esc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    buf = (char * ) esc_buf_get_data(ciphertext_p);

    printf("ciphertext:\n");
    for (size_t i = 0; i < esc_buf_get_len(ciphertext_p); i++) {
      printf("0x%02X ", buf[i]);
    }
    printf("\n");

    if (esc_message_decrypt_from_serialized(ciphertext_p, &addr_b, ctx_a_p, &plaintext_p)) {
      fprintf(stderr, "failed to decrypt message from bob to alice\n");
      esc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    printf("received reply from bob: %s\n", esc_buf_get_data(plaintext_p));

    printf("enter message: ");
  }

  printf("done, exiting.");
  esc_cleanup(ctx_a_p);
  esc_cleanup(ctx_b_p);
}
