#include "cpuinfo_aarch64.h"

using namespace cpu_features;

extern "C" {

int aes_hardware_supported() {
    static const Aarch64Info info = GetAarch64Info();
    return info.features.aes;
}

}