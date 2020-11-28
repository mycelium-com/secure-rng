#include "cpuinfo_x86.h"

using namespace cpu_features;

extern "C" {

int aes_hardware_supported() {
    static const X86Info info = GetX86Info();
    return info.features.aes;
}

}