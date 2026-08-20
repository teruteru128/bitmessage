#ifndef BM_CORE_MESSAGES_STORE_H
#define BM_CORE_MESSAGES_STORE_H

/* messages.db(§2.4)の操作。CRUD関数はmessage_builder/trial_decrypt実装後にTODO。 */

#include <sqlite3.h>

int bm_messages_store_init_schema(sqlite3 *db);

#endif /* BM_CORE_MESSAGES_STORE_H */
