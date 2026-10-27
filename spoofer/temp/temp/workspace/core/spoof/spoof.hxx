#pragma once
#include "helpers.hxx"
#include "smbios.hxx"
#include "efi.hxx"
#include "boot.hxx"
#include "disk/disk.hxx"
#include "nic.hxx"
#include "uuid_cache.hxx"
#include "arp.hxx"
#include "monitor.hxx"
#include "usb.hxx"
#include "volume_guid.hxx"
#include "product_id.hxx"
#include "registry_ids.hxx"
#include "usn_journal.hxx"
#include "filetimes.hxx"
#include "artifacts.hxx"
#include "trace_ids.hxx"
#include "bluetooth.hxx"
#include "tpm.hxx"
#include "wmi_cimom.hxx"
#include "hostname.hxx"
#include "acpi.hxx"

namespace spoof {

    inline bool install() {
        struct stage_result {
            const char* name;
            long long elapsed_ms;
        };

        std::vector<stage_result> stages;
        const auto run_started = std::chrono::steady_clock::now();

        auto run_stage = [&](std::uint32_t current, const char* name, auto&& fn) {
            logging::stage(current, 25, "%s", name);
            const auto started = std::chrono::steady_clock::now();
            fn();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started).count();

            stages.push_back({ name, static_cast<long long>(elapsed) });
            logging::success("run: %s completed in %lldms", name, static_cast<long long>(elapsed));
        };

        logging::blank();
        logging::info("run: starting hardware spoof");

        if (!helpers::setup_helpers()) {
            logging::error("run: helper setup failed");
            return false;
        }

        helpers::init_rng();

        run_stage(1, "SMBIOS", [] { smbios::install(); });
        run_stage(2, "EFI", [] { efi::install(); });
        run_stage(3, "boot identifiers", [] { boot::install(); });
        run_stage(4, "disk", [] { disk::install(); });
        //run_stage(5, "NIC", [] { nic::install(); });
        run_stage(6, "UUID cache", [] { uuid_cache::install(nic::s_first_mac); });
        run_stage(7, "ARP neighbor cache", [] { arp::install(); });
        run_stage(8, "monitor EDID", [] { monitor::install(); });
        run_stage(9, "USB storage serials", [] { usb::install(); });
        run_stage(10, "volume GUIDs", [] { volume_guid::install(); });
        run_stage(11, "Windows ProductId", [] { product_id::install(); });
        run_stage(12, "trace IDs",        [] { trace_ids::install(); });
        run_stage(13, "registry IDs",     [] { registry_ids::install(); });
        run_stage(14, "USN journal",      [] { usn_journal::install(); });
        run_stage(15, "file timestamps",  [] { filetimes::install(); });
        run_stage(16, "artifacts",        [] { artifacts::install(); });
        run_stage(17, "Bluetooth",        [] { bluetooth::install(); });
        run_stage(18, "TPM",              [] { tpm::install(); });
        run_stage(19, "WMI CIMOM cache",  [] { wmi_cimom::install(); });
        run_stage(20, "hostname",         [] { hostname::install(); });
        run_stage(21, "ACPI tables",      [] { acpi::install(); });

        const auto total_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - run_started).count();

        logging::blank();
        logging::success("run: hardware spoof complete in %lldms", static_cast<long long>(total_elapsed));
        logging::info("summary: %zu stages, %u warning(s), %u error(s)",
            stages.size(), logging::warning_count(), logging::error_count());

        for (const auto& stage : stages)
            logging::info("summary: %-20s %lldms", stage.name, stage.elapsed_ms);

        logging::info("summary: full log written to temp.log");

        return true;
    }

}
