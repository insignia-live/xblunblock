#include <stdint.h>
#include <stdbool.h>

#include <hal/debug.h>
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
    for (uint8_t *kernelPtr = (uint8_t *)0x80010000; (uint32_t)kernelPtr < *((uint32_t *)0x80010158) - 6 + 0x80010000; kernelPtr++) {
        if (checkSig(kernelPtr)) {
            debugPrint("XONLINE signature found: %x\n", kernelPtr);
            return kernelPtr;
        }
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

    XboxHardwareInfo.Flags &= ~XBOX_HW_FLAG_DEVKIT_KERNEL;

    enable_protection();
}

int main (void)
{
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
    }

    debugPrint("\n We're done here. Rebooting in");
    for (int i = 10; i > 0; i++) {
        Sleep(1000);
    }
    XReboot();

    return 0;
}