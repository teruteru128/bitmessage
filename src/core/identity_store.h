#ifndef BM_CORE_IDENTITY_STORE_H
#define BM_CORE_IDENTITY_STORE_H

/* identity.db(§2.3)の操作。CRUD関数はkeyring実装後にTODO。 */

#include <sqlite3.h>

int bm_identity_store_init_schema(sqlite3 *db);

#endif /* BM_CORE_IDENTITY_STORE_H */
