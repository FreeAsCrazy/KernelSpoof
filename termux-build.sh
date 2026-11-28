#!/bin/sh
set -eu
cd "$(dirname "$0")"

name=$(sed -n 's/.*#define KS_NAME "\([^"]*\)".*/\1/p' KernelSpoof.c | head -n1)
ver=$(sed -n 's/.*KPM_VERSION("\([^"]*\)").*/\1/p' KernelSpoof.c | head -n1)
[ -n "$name" ] && [ -n "$ver" ] || {
    echo "error: KS_NAME/KPM_VERSION missing" >&2
    exit 1
}

kpm=${name}_${ver}.kpm
kp=${KP_DIR:-../KernelPatch}

aarch64-linux-android-gcc -O2 \
    -fno-pic -fno-PIC \
    -fno-stack-protector \
    -fno-asynchronous-unwind-tables \
    -fno-unwind-tables \
    -fno-builtin \
    -I"$kp/kernel/." \
    -I"$kp/kernel/include" \
    -I"$kp/kernel/patch/include" \
    -I"$kp/kernel/linux/include" \
    -I"$kp/kernel/linux/arch/arm64/include" \
    -I"$kp/kernel/linux/tools/arch/arm64/include" \
    -c KernelSpoof.c -o KernelSpoof.o

aarch64-linux-android-gcc -r -nostdlib -Wl,--no-eh-frame-hdr \
    -o "$kpm" KernelSpoof.o
rm -f KernelSpoof.o

llvm-objcopy \
    --remove-section=.eh_frame \
    --remove-section=.eh_frame_hdr \
    --remove-section=.rela.eh_frame \
    "$kpm"

if readelf -rW "$kpm" | grep -q 'R_AARCH64_ADR_GOT_PAGE'; then
    echo "error: $kpm still contains R_AARCH64_ADR_GOT_PAGE" >&2
    exit 1
fi

echo "built: $(pwd)/$kpm"
