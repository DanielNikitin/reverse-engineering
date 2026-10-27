#pragma once
#include "helpers.hxx"

namespace boot {

    static constexpr std::uint64_t KUSER_SHARED_DATA_VA = 0xFFFFF78000000000ULL;
    static constexpr std::uint32_t BOOT_ID_OFF          = 0x2C4u;

    inline void install() {
        using namespace spoof::helpers;

        const std::uint32_t new_id = (rand_next() % 9998) + 1;
        kwrite_val<std::uint32_t>(KUSER_SHARED_DATA_VA + BOOT_ID_OFF, new_id);
        logging::print("spoof: BootId -> %u", new_id);

        const std::uint64_t ke_boot_va = pdb::get_symbol_address("KeBootTime");
        if (ke_boot_va) {
            const std::int64_t cur = static_cast<std::int64_t>(kread_val<std::uint64_t>(ke_boot_va));
            if (cur) {

                const std::int64_t days  = static_cast<std::int64_t>((rand_next() % 30) + 1);
                const std::int64_t sign  = (rand_next() & 1) ? 1LL : -1LL;
                const std::int64_t delta = sign * days * 864000000000LL;
                kwrite_val<std::int64_t>(ke_boot_va, cur + delta);
                logging::print("spoof: KeBootTime shifted by %+lld days", static_cast<long long>(sign * days));
            }
        } else {
            logging::print("spoof: KeBootTime symbol not found — skipping");
        }
    }

}
