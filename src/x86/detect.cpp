#ifdef __linux
// Include HWCAP related headers on linux and android
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

extern "C" {

int aes_hardware_supported() {
#ifdef __linux
    return getauxval(AT_HWCAP) & HWCAP_AES; // Use HWCAP on linux
#else
    return true; // No detection for now
#endif
}

}
