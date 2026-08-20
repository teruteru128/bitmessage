#include "object.h"

enum bm_propagation_mode bm_decide_propagation(const unsigned char object_hash[32],
                                                const struct bm_fd_data *target_connection)
{
    (void)object_hash;
    (void)target_connection;
    /* TODO(§9): Dandelion++実装時、stem状態(struct dandelion_state)を見て
     * PROPAGATE_STEM/PROPAGATE_SKIPを返すよう差し替える。v1は常時fluff。 */
    return BM_PROPAGATE_FLUFF;
}
