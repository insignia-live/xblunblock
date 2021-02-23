#include <stdint.h>
#include <stdbool.h>

#include <hal/debug.h>
#include <hal/video.h>
#include <hal/xbox.h>
#include <windows.h>

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

bool checkSig (const uint8_t *ptr)
{
    const uint8_t xonline_signature[] = {'X', 'O', 'N', 'L', 'I', 'N', 'E'};

    for (size_t i = 0; i < 7; i++) {
        if (xonline_signature[i] != ptr[i]) return false;
    }

    return true;
}

void *find_XONLINE ()
{
    uint32_t *e_lfanew_p = (uint32_t *)0x8001003c;
    uint32_t *size_of_image = (uint32_t *)(0x80010000 + *e_lfanew_p + 0x50);

    __try {
        for (uint8_t *kernelPtr = (uint8_t *)0x80010000; (uint32_t)kernelPtr < *size_of_image - 7 + 0x80010000; kernelPtr++) {
            if (checkSig(kernelPtr)) {
                debugPrint("XONLINE signature found: %x\n", kernelPtr);
                return kernelPtr;
            }
        }
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) {
        return NULL;
    }

    return NULL;
}

void patch_XONLINE (void *addr)
{
    disable_protection();

    // Patch to "XINLINE" :D
    ((uint8_t *)addr)[1] = 'I';

    enable_protection();
}

bool has_devkit_flag ()
{
    return XboxHardwareInfo.Flags & XBOX_HW_FLAG_DEVKIT_KERNEL;
}

void patch_devkit_flag ()
{
    disable_protection();

    // Won't persist.
    XboxHardwareInfo.Flags &= ~XBOX_HW_FLAG_DEVKIT_KERNEL;

    enable_protection();
}

bool checkDevkitSig (const uint8_t *ptr)
{
    uint32_t ordinal_322_addr = (uint32_t)&XboxHardwareInfo;
    uint8_t *bytes = (uint8_t *)&ordinal_322_addr;

    const uint8_t devkit_instruction_signature[] = {0x83, 0x0d, bytes[0], bytes[1], bytes[2], bytes[3], 0x02};

    for (size_t i = 0; i < 7; i++) {
        if (devkit_instruction_signature[i] != ptr[i]) return false;
    }

    return true;
}


void *find_devkit_flag_instruction ()
{
    uint32_t *e_lfanew_p = (uint32_t *)0x8001003c;
    uint32_t *size_of_image = (uint32_t *)(0x80010000 + *e_lfanew_p + 0x50);

    debugPrint("%x\n", *size_of_image - 7 + 0x80010000);

    __try {
        for (uint8_t *kernelPtr = (uint8_t *)0x80010000; (uint32_t)kernelPtr < *size_of_image - 7 + 0x80010000; kernelPtr++) {
            if (checkDevkitSig(kernelPtr)) {
                debugPrint("devkit flag instruction signature found: %x\n", kernelPtr);
                return kernelPtr;
            }
        }
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) {
        return NULL;
    }

    return NULL;
}

void patch_devkit_instruction (uint8_t *addr)
{
    disable_protection();

    for (size_t i = 0; i < 7; i++) {
        addr[i] = 0x90;
    }

    enable_protection();
}

bool checkDashSig (const uint8_t *ptr)
{
    uint32_t ordinal_322_addr = (uint32_t)&XboxHardwareInfo;
    uint8_t *bytes = (uint8_t *)&ordinal_322_addr;

    const uint8_t devkit_instruction_signature[] = {0xa1, 0x18, 0x01, 0x01, 0x00, 0x81, 0x78, 0x08, 0x00, 0x00, 0xfe, 0xff, 0x75};

    for (size_t i = 0; i < 13; i++) {
        if (devkit_instruction_signature[i] != ptr[i]) return false;
    }

    return true;
}

void *find_dashboard_detection()
{
    uint32_t *e_lfanew_p = (uint32_t *)0x8001003c;
    uint32_t *size_of_image = (uint32_t *)(0x80010000 + *e_lfanew_p + 0x50);

    __try {
        for (uint8_t *kernelPtr = (uint8_t *)0x80010000; (uint32_t)kernelPtr < *size_of_image - 13 + 0x80010000; kernelPtr++) {
            if (checkDashSig(kernelPtr)) {
                debugPrint("dashboard check instruction signature found: %x\n", kernelPtr);
                return kernelPtr;
            }
        }
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION) {
        return NULL;
    }

    return NULL;
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
    void *xonline_signature = find_XONLINE();
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
    void *devkit_instruction = find_devkit_flag_instruction();
    if (devkit_instruction) {
        debugPrint("Found. MACS wouldn't work. Patching...\n");
        patch_devkit_instruction(devkit_instruction);
        debugPrint("Done. MACS should work now.\n");
    } else {
        debugPrint("Not found, maybe it'll work, maybe not.\n");
    }

    debugPrint("Checking for dashboard detection code...\n");
    void *dashboard_detection;
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