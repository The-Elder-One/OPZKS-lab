#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libakrypt.h>

#define PORT 12345

static ssize_t recv_all(int fd, void *buf, size_t len) {
    size_t total = 0;
    ssize_t n;
    char *ptr = (char *)buf;
    while (total < len) {
        n = recv(fd, ptr + total, len - total, 0);
        if (n <= 0) return (n < 0) ? -1 : 0;
        total += n;
    }
    return total;
}

static ssize_t send_all(int fd, const void *buf, size_t len) {
    size_t total = 0;
    ssize_t n;
    const char *ptr = (const char *)buf;
    while (total < len) {
        n = send(fd, ptr + total, len - total, 0);
        if (n <= 0) return (n < 0) ? -1 : 0;
        total += n;
    }
    return total;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    ak_uint8 key[32];

    FILE *key_file = fopen("key.bin", "rb");
    if (!key_file) {
        perror("Ошибка открытия файла ключа");
        return EXIT_FAILURE;
    }
    if (fread(key, 1, 32, key_file) != 32) {
        fprintf(stderr, "Ошибка чтения ключа\n");
        fclose(key_file);
        return EXIT_FAILURE;
    }
    fclose(key_file);

    if (ak_libakrypt_create(NULL) != ak_true) {
        fprintf(stderr, "Ошибка инициализации libakrypt\n");
        return EXIT_FAILURE;
    }
    printf("[СЕРВЕР] Библиотека инициализирована.\n");

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Ошибка создания сокета");
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    printf("[СЕРВЕР] Сокет создан.\n");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Ошибка привязки");
        close(server_fd);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    printf("[СЕРВЕР] Привязка к порту %d выполнена.\n", PORT);

    if (listen(server_fd, 3) < 0) {
        perror("Ошибка прослушивания");
        close(server_fd);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    printf("[СЕРВЕР] Ожидание подключений...\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (new_socket < 0) {
            perror("[СЕРВЕР] Ошибка accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("[СЕРВЕР] Подключился клиент %s\n", client_ip);

        ak_uint8 iv[16];
        if (recv_all(new_socket, iv, sizeof(iv)) != (ssize_t)sizeof(iv)) {
            printf("[СЕРВЕР] Ошибка чтения IV\n");
            close(new_socket);
            continue;
        }

        uint32_t netlen;
        if (recv_all(new_socket, &netlen, sizeof(netlen)) != (ssize_t)sizeof(netlen)) {
            printf("[СЕРВЕР] Ошибка чтения длины\n");
            close(new_socket);
            continue;
        }
        size_t total_len = ntohl(netlen);

        ak_uint8 *ciphertext = malloc(total_len);
        if (!ciphertext) {
            printf("[СЕРВЕР] Ошибка памяти под ciphertext\n");
            close(new_socket);
            continue;
        }

        if (recv_all(new_socket, ciphertext, total_len) != (ssize_t)total_len) {
            printf("[СЕРВЕР] Ошибка чтения ciphertext\n");
            free(ciphertext);
            close(new_socket);
            continue;
        }

        ak_uint8 mac[16];
        if (recv_all(new_socket, mac, sizeof(mac)) != (ssize_t)sizeof(mac)) {
            printf("[СЕРВЕР] Ошибка чтения MAC\n");
            free(ciphertext);
            close(new_socket);
            continue;
        }

        struct bckey bkey;
        if (ak_bckey_create_kuznechik(&bkey) != ak_error_ok) {
            fprintf(stderr, "[СЕРВЕР] Ошибка создания ключа\n");
            free(ciphertext);
            close(new_socket);
            continue;
        }
        if (ak_bckey_set_key(&bkey, key, 32) != ak_error_ok) {
            fprintf(stderr, "[СЕРВЕР] Ошибка установки ключа\n");
            ak_bckey_destroy(&bkey);
            free(ciphertext);
            close(new_socket);
            continue;
        }

        ak_uint8 computed_mac[16];
        if (ak_bckey_cmac(&bkey, ciphertext, total_len, computed_mac, sizeof(computed_mac)) != ak_error_ok) {
            printf("[СЕРВЕР] Ошибка вычисления MAC\n");
            ak_bckey_destroy(&bkey);
            free(ciphertext);
            close(new_socket);
            continue;
        }

        if (memcmp(mac, computed_mac, sizeof(mac)) != 0) {
            printf("[СЕРВЕР] MAC не совпадает! Сообщение от %s отброшено.\n", client_ip);
            ak_bckey_destroy(&bkey);
            free(ciphertext);
            close(new_socket);
            continue;
        }

        ak_uint8 *plaintext = malloc(total_len);
        if (!plaintext) {
            printf("[СЕРВЕР] Ошибка памяти под plaintext\n");
            ak_bckey_destroy(&bkey);
            free(ciphertext);
            close(new_socket);
            continue;
        }

        if (ak_bckey_decrypt_cbc(&bkey, ciphertext, plaintext, total_len, iv, sizeof(iv)) != ak_error_ok) {
            printf("[СЕРВЕР] Ошибка расшифровки\n");
            ak_bckey_destroy(&bkey);
            free(ciphertext);
            free(plaintext);
            close(new_socket);
            continue;
        }

        size_t padding = plaintext[total_len - 1];
        size_t msg_len = total_len - padding;
        plaintext[msg_len] = '\0';

        printf("[СЕРВЕР] Сообщение от %s: \"%s\"\n", client_ip, plaintext);

        // Отправляем ответ
        const char *resp_msg = "Принято!";
        size_t resp_msg_len = strlen(resp_msg);
        size_t resp_padding = 16 - (resp_msg_len % 16);
        size_t resp_len = resp_msg_len + resp_padding;
        ak_uint8 *resp_padded = malloc(resp_len);
        memcpy(resp_padded, resp_msg, resp_msg_len);
        memset(resp_padded + resp_msg_len, resp_padding, resp_padding);

        struct random gen;
        ak_random_create_lcg(&gen);
        ak_uint8 response_iv[16];
        ak_random_ptr(&gen, response_iv, sizeof(response_iv));
        ak_random_destroy(&gen);

        if (ak_bckey_encrypt_cbc(&bkey, resp_padded, ciphertext, resp_len, response_iv, sizeof(response_iv)) != ak_error_ok) {
            printf("[СЕРВЕР] Ошибка шифрования ответа\n");
            free(resp_padded);
            ak_bckey_destroy(&bkey);
            free(ciphertext);
            free(plaintext);
            close(new_socket);
            continue;
        }

        if (ak_bckey_cmac(&bkey, ciphertext, resp_len, computed_mac, sizeof(computed_mac)) != ak_error_ok) {
            printf("[СЕРВЕР] Ошибка вычисления MAC ответа\n");
            free(resp_padded);
            ak_bckey_destroy(&bkey);
            free(ciphertext);
            free(plaintext);
            close(new_socket);
            continue;
        }

        uint32_t resp_netlen = htonl((uint32_t)resp_len);
        send_all(new_socket, response_iv, sizeof(response_iv));
        send_all(new_socket, &resp_netlen, sizeof(resp_netlen));
        send_all(new_socket, ciphertext, resp_len);
        send_all(new_socket, computed_mac, sizeof(computed_mac));

        free(resp_padded);
        ak_bckey_destroy(&bkey);
        free(ciphertext);
        free(plaintext);
        close(new_socket);
        printf("[СЕРВЕР] Соединение с %s закрыто.\n", client_ip);
    }

    ak_libakrypt_destroy();
    return 0;
}
