/*
 * core/messages_store.c のアドレス帳(address_book)CRUD単体テスト。§11 2026-08-29実装。
 * PyBitmessage本家api.pyのaddAddressBookEntry(重複禁止)/deleteAddressBookEntry(存在しなくても
 * エラーにしない)/listAddressBookEntries準拠であることを検証する。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/messages_store.h"

#define TEST_DB_PATH "test_address_book_messages.db"

static sqlite3 *open_fresh_db(void)
{
    unlink(TEST_DB_PATH);
    sqlite3 *db = NULL;
    if (sqlite3_open(TEST_DB_PATH, &db) != SQLITE_OK)
    {
        fprintf(stderr, "FAIL: sqlite3_open\n");
        exit(EXIT_FAILURE);
    }
    if (bm_messages_store_init_schema(db) != 0)
    {
        fprintf(stderr, "FAIL: init_schema\n");
        exit(EXIT_FAILURE);
    }
    return db;
}

int main(void)
{
    sqlite3 *db = open_fresh_db();

    const char *addr1 = "BM-2cVprb4EsXsaQ4WXfhQ5SX2iTAqxmrJp9J";
    const char *addr2 = "BM-2cTHTgLZfxdxLR4NKuMEnAAmM4gBLpJk3f";

    if (bm_messages_store_add_address_book_entry(db, addr1, "friend A") != 0)
    {
        fprintf(stderr, "FAIL: add_address_book_entry(addr1)\n");
        return EXIT_FAILURE;
    }
    printf("OK: アドレス帳へ新規追加\n");

    /* 重複addは失敗する(PyBitmessage本家addAddressBookEntry準拠、UPSERTしない) */
    if (bm_messages_store_add_address_book_entry(db, addr1, "duplicate") == 0)
    {
        fprintf(stderr, "FAIL: duplicate add should fail\n");
        return EXIT_FAILURE;
    }
    printf("OK: 重複addressのaddは失敗する\n");

    if (bm_messages_store_add_address_book_entry(db, addr2, "friend B") != 0)
    {
        fprintf(stderr, "FAIL: add_address_book_entry(addr2)\n");
        return EXIT_FAILURE;
    }

    struct bm_address_book_entry *list = NULL;
    size_t count = 0;
    if (bm_messages_store_list_address_book(db, &list, &count) != 0 || count != 2)
    {
        fprintf(stderr, "FAIL: list_address_book count=%zu (expected 2)\n", count);
        return EXIT_FAILURE;
    }
    int found1 = 0;
    int found2 = 0;
    for (size_t i = 0; i < count; i++)
    {
        if (strcmp(list[i].address, addr1) == 0 && strcmp(list[i].label, "friend A") == 0)
        {
            found1 = 1;
        }
        if (strcmp(list[i].address, addr2) == 0 && strcmp(list[i].label, "friend B") == 0)
        {
            found2 = 1;
        }
    }
    bm_address_book_list_free(list);
    if (!found1 || !found2)
    {
        fprintf(stderr, "FAIL: list_address_book entries do not match what was added\n");
        return EXIT_FAILURE;
    }
    printf("OK: 追加した2件がlabel込みで正しく一覧される\n");

    if (bm_messages_store_remove_address_book_entry(db, addr1) != 0)
    {
        fprintf(stderr, "FAIL: remove_address_book_entry(addr1)\n");
        return EXIT_FAILURE;
    }

    /* 存在しないaddressのremoveもエラーにしない(PyBitmessage本家deleteAddressBookEntry準拠) */
    if (bm_messages_store_remove_address_book_entry(db, addr1) != 0)
    {
        fprintf(stderr, "FAIL: removing an already-removed address should not error\n");
        return EXIT_FAILURE;
    }
    printf("OK: removeは冪等(存在しないaddressでもエラーにしない)\n");

    list = NULL;
    count = 0;
    if (bm_messages_store_list_address_book(db, &list, &count) != 0 || count != 1
        || strcmp(list[0].address, addr2) != 0)
    {
        fprintf(stderr, "FAIL: after removing addr1, only addr2 should remain\n");
        bm_address_book_list_free(list);
        return EXIT_FAILURE;
    }
    bm_address_book_list_free(list);
    printf("OK: remove後は残り1件のみ一覧される\n");

    sqlite3_close(db);
    unlink(TEST_DB_PATH);

    printf("ALL OK\n");
    return EXIT_SUCCESS;
}
