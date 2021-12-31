#include <array>

#include <stdint.h>
#include <stdbool.h>

#include <hal/debug.h>
#include <hal/video.h>
#include <hal/xbox.h>
#include <windows.h>

const uint32_t kernel_start = (uint32_t)0x80010000;
PIMAGE_DOS_HEADER kernel_dos_header = (PIMAGE_DOS_HEADER)kernel_start;
PIMAGE_NT_HEADERS32 kernel_nt_header = (PIMAGE_NT_HEADERS32)((uint32_t)kernel_dos_header + kernel_dos_header->e_lfanew);

const std::array<uint8_t, 7> xonline_signature = {'X', 'O', 'N', 'L', 'I', 'N', 'E'};
const std::array<uint8_t, 13> dashboard_detection_signature = {0xa1, 0x18, 0x01, 0x01, 0x00, 0x81, 0x78, 0x08, 0x00, 0x00, 0xfe, 0xff, 0x75};
uint32_t ordinal_322_addr = (uint32_t)&XboxHardwareInfo;
uint8_t *bytes = (uint8_t *)&ordinal_322_addr;
const std::array<uint8_t, 7> devkit_instruction_signature = {0x83, 0x0d, bytes[0], bytes[1], bytes[2], bytes[3], 0x02};

void disable_protection ()
{
    asm volatile (
        "cli;"
        "movl %%cr0, %%eax;"
        "andl $0xFFFEFFFF, %%eax;"
        "movl %%eax, %%cr0;"
        : : : "eax", "memory");
}

void enable_protection ()
{
    asm volatile (
        "movl %%cr0, %%eax;"
        "orl $0x00010000, %%eax;"
        "movl %%eax, %%cr0;"
        "sti;"
        : : : "eax", "memory");
}

template <typename T, size_t size>
bool check_sig (const std::array<T, size> &signature, const uint8_t *ptr)
{
    for (size_t i = 0; i < size; i++) {
        if (signature[i] != ptr[i]) return false;
    }

    return true;
}

template <typename T, size_t size>
uint8_t *find_sig (const std::array<T, size> &signature)
{
    __try {
        for (uint8_t *kernelptr = (uint8_t *)kernel_start; (uint32_t)kernelptr < kernel_start + kernel_nt_header->OptionalHeader.SizeOfImage - size; kernelptr++) {
            if (check_sig(signature, kernelptr)) {
                return kernelptr;
            }
        }
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) {
        return nullptr;
    }

    return nullptr;
}

uint8_t *find_XONLINE ()
{
    uint8_t *xonline_addr = find_sig(xonline_signature);

    if (xonline_addr) {
        debugPrint("XONLINE signature found: %x\n", (uint32_t)xonline_addr);
    }

    return xonline_addr;
}

void patch_XONLINE (uint8_t *addr)
{
    disable_protection();

    // Patch to "XINLINE" :D
    addr[1] = 'I';

    enable_protection();
}

bool has_devkit_flag ()
{
    return XboxHardwareInfo.Flags & XBOX_HW_FLAG_DEVKIT_KERNEL;
}

void patch_devkit_flag ()
{
    disable_protection();

    // Won't persist without also patching the instruction that sets it
    XboxHardwareInfo.Flags &= ~XBOX_HW_FLAG_DEVKIT_KERNEL;

    enable_protection();
}

uint8_t *find_devkit_flag_instruction ()
{
    uint8_t *devinstr_addr = find_sig(devkit_instruction_signature);

    if (devinstr_addr) {
        debugPrint("devkit flag instruction signature found: %x\n", (uint32_t)devinstr_addr);
    }

    return devinstr_addr;
}

void patch_devkit_instruction (uint8_t *addr)
{
    disable_protection();

    // Replace all of it with NOPs
    for (size_t i = 0; i < devkit_instruction_signature.size(); i++) {
        addr[i] = 0x90;
    }

    enable_protection();
}

uint8_t *find_dashboard_detection()
{
    uint8_t *dashcheck_addr = find_sig(dashboard_detection_signature);

    if (dashcheck_addr) {
        debugPrint("dashboard check instruction signature found: %x\n", (uint32_t)dashcheck_addr);
    }

    return dashcheck_addr;
}

void patch_dashboard_detection (uint8_t *addr)
{
    disable_protection();

    // patch the jnz after cmp to jmp
    addr[12] = 0xeb;

    enable_protection();
}

int main (void)
{
    XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);

    debugPrint("Checking for XONLINE signature...\n");
    uint8_t *xonline_signature = find_XONLINE();
    if (xonline_signature) {
        debugPrint("Found. Your BIOS may block XBL. Patching...\n");
        patch_XONLINE(xonline_signature);
        debugPrint("Done. XBL should be unblocked now.\n");
    } else {
        debugPrint("Not found, you should be fine.\n");
    }

    debugPrint("Checking devkit flag...\n");
    if (has_devkit_flag()) {
        debugPrint("Found. MACS wouldn't work. Patching...\n");
        patch_devkit_flag();
        debugPrint("Done. MACS should now work.\n");
    } else {
        debugPrint("Not found, you should be fine.\n");
    }

    debugPrint("Checking for devkit flag set instruction...\n");
    uint8_t *devkit_instruction = find_devkit_flag_instruction();
    if (devkit_instruction) {
        debugPrint("Found. MACS wouldn't work. Patching...\n");
        patch_devkit_instruction(devkit_instruction);
        debugPrint("Done. MACS should work now.\n");
    } else {
        debugPrint("Not found, maybe it'll work, maybe not.\n");
    }

    debugPrint("Checking for dashboard detection code...\n");
    uint8_t *dashboard_detection;
    while ((dashboard_detection = find_dashboard_detection())) {
        debugPrint("Found. Patching...\n");
        patch_dashboard_detection(dashboard_detection);
    }


    debugPrint("\nWe're done here. Rebooting in");
    for (int i = 10; i > 0; i--) {
        debugPrint(" %d", i);
        Sleep(1000);
    }

    HalReturnToFirmware(HalQuickRebootRoutine);

    return 0;
}
