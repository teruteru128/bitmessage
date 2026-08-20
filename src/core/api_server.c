#include "api_server.h"

#include <stddef.h>

void *bm_api_server_thread(void *arg)
{
    (void)arg;
    /* TODO(§6): apiinterface:apiportでJSON-RPC 2.0サーバーを待受ける。
     * §6.2の鍵ライフサイクル系メソッドを含むハンドラ辞書を実装する。 */
    return NULL;
}
