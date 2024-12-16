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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Использование: %s <IP-адрес сервера>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *server_ip = argv[1];

    int sock = 0;
    struct sockaddr_in serv_addr;
    ak_uint8 key[32];
    ak_uint8 iv[16];
    char message[1024];
    ak_uint8 ciphertext[1024];
    ak_uint8 mac[16];
    size_t message_len;
    size_t total_len;

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

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Ошибка создания сокета\n");
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        printf("Неверный адрес\n");
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Ошибка подключения\n");
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    printf("Введите сообщение для отправки серверу: ");
    if (!fgets(message, sizeof(message), stdin)) {
        printf("Ошибка чтения сообщения\n");
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    message_len = strlen(message);
    if (message_len > 0 && message[message_len - 1] == '\n') {
        message[message_len - 1] = '\0';
        message_len--;
    }

    struct random generator;
    if (ak_random_create_lcg(&generator) != ak_error_ok) {
        fprintf(stderr, "Ошибка генератора\n");
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    if (ak_random_ptr(&generator, iv, sizeof(iv)) != ak_error_ok) {
        fprintf(stderr, "Ошибка генерации IV\n");
        ak_random_destroy(&generator);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    ak_random_destroy(&generator);

    struct bckey bkey;
    if (ak_bckey_create_kuznechik(&bkey) != ak_error_ok) {
        fprintf(stderr, "Ошибка создания ключа\n");
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    if (ak_bckey_set_key(&bkey, key, sizeof(key)) != ak_error_ok) {
        fprintf(stderr, "Ошибка установки ключа\n");
        ak_bckey_destroy(&bkey);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    size_t padding = 16 - (message_len % 16);
    total_len = message_len + padding;
    ak_uint8 *padded_message = malloc(total_len);
    memcpy(padded_message, message, message_len);
    memset(padded_message + message_len, padding, padding);

    if (ak_bckey_encrypt_cbc(&bkey, padded_message, ciphertext, total_len, iv, sizeof(iv)) != ak_error_ok) {
        fprintf(stderr, "Ошибка шифрования\n");
        free(padded_message);
        ak_bckey_destroy(&bkey);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    if (ak_bckey_cmac(&bkey, ciphertext, total_len, mac, sizeof(mac)) != ak_error_ok) {
        fprintf(stderr, "Ошибка вычисления MAC\n");
        free(padded_message);
        ak_bckey_destroy(&bkey);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    free(padded_message);
    ak_bckey_destroy(&bkey);

    // Отправка
    if (send_all(sock, iv, sizeof(iv)) != (ssize_t)sizeof(iv)) {
        printf("Ошибка отправки IV\n");
    }
    uint32_t netlen = htonl((uint32_t)total_len);
    if (send_all(sock, &netlen, sizeof(netlen)) != (ssize_t)sizeof(netlen)) {
        printf("Ошибка отправки длины\n");
    }
    if (send_all(sock, ciphertext, total_len) != (ssize_t)total_len) {
        printf("Ошибка отправки ciphertext\n");
    }
    if (send_all(sock, mac, sizeof(mac)) != (ssize_t)sizeof(mac)) {
        printf("Ошибка отправки MAC\n");
    }

    // Получение ответа
    ak_uint8 resp_iv[16];
    if (recv_all(sock, resp_iv, sizeof(resp_iv)) != (ssize_t)sizeof(resp_iv)) {
        printf("Ошибка чтения IV ответа\n");
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    uint32_t resp_netlen;
    if (recv_all(sock, &resp_netlen, sizeof(resp_netlen)) != (ssize_t)sizeof(resp_netlen)) {
        printf("Ошибка чтения длины ответа\n");
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    size_t resp_len = ntohl(resp_netlen);

    ak_uint8 *resp_ct = malloc(resp_len);
    if (!resp_ct) {
        printf("Ошибка памяти под resp_ct\n");
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    if (recv_all(sock, resp_ct, resp_len) != (ssize_t)resp_len) {
        printf("Ошибка чтения ciphertext ответа\n");
        free(resp_ct);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    ak_uint8 resp_mac[16];
    if (recv_all(sock, resp_mac, sizeof(resp_mac)) != (ssize_t)sizeof(resp_mac)) {
        printf("Ошибка чтения MAC ответа\n");
        free(resp_ct);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    if (ak_bckey_create_kuznechik(&bkey) != ak_error_ok) {
        fprintf(stderr, "Ошибка создания ключа\n");
        free(resp_ct);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    if (ak_bckey_set_key(&bkey, key, 32) != ak_error_ok) {
        fprintf(stderr, "Ошибка установки ключа\n");
        ak_bckey_destroy(&bkey);
        free(resp_ct);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    ak_uint8 check_mac[16];
    if (ak_bckey_cmac(&bkey, resp_ct, resp_len, check_mac, sizeof(check_mac)) != ak_error_ok) {
        printf("Ошибка вычисления MAC ответа\n");
        ak_bckey_destroy(&bkey);
        free(resp_ct);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    if (memcmp(resp_mac, check_mac, sizeof(resp_mac)) != 0) {
        printf("MAC ответа не совпадает\n");
        ak_bckey_destroy(&bkey);
        free(resp_ct);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    ak_uint8 *resp_pt = malloc(resp_len);
    if (!resp_pt) {
        printf("Ошибка памяти под resp_pt\n");
        ak_bckey_destroy(&bkey);
        free(resp_ct);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    if (ak_bckey_decrypt_cbc(&bkey, resp_ct, resp_pt, resp_len, resp_iv, sizeof(resp_iv)) != ak_error_ok) {
        printf("Ошибка расшифровки ответа\n");
        ak_bckey_destroy(&bkey);
        free(resp_ct);
        free(resp_pt);
        close(sock);
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    size_t resp_pad = resp_pt[resp_len - 1];
    size_t resp_msg_len = resp_len - resp_pad;
    resp_pt[resp_msg_len] = '\0';

    printf("Ответ сервера: \"%s\"\n", resp_pt);

    ak_bckey_destroy(&bkey);
    free(resp_ct);
    free(resp_pt);
    close(sock);
    ak_libakrypt_destroy();
    return 0;
}
