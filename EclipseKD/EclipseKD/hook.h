#pragma once

/*
 * hook.h — Hook namespace prototypes.
 */

#include "definitions.h"

namespace Hook {

    // Install the dxgkrnl hook (PTE primary, inline fallback)
    BOOLEAN Install(PVOID handlerAddr);

    // Command dispatcher — called when hooked function is invoked
    NTSTATUS Handler(PVOID data);

} // namespace Hook
