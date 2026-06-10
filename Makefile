# idps-fw-test — firewall functional-test toolset for idps-fw.
#
# Usage: make <target> [platform=host|android]
#
# Deliverables:
#   fw-verify   host orchestrator (pure Rust; cross-builds to Windows .exe)
#   fw-agent    on-device worker (cross-built to aarch64-linux-android)
#
# `make package-android` cross-builds fw-agent + fw-verify.exe and bundles an
# Android system.zip payload + Windows install.bat + a distributable zip.

platform ?= host
BIN_INSTALL_DIR ?= /usr/local/bin
ANDROID_BIN_INSTALL_DIR ?= /system/bin
ANDROID_PACKAGE_OUT ?= $(abspath out/idps-fw-test)
ANDROID_PACKAGE_ZIP ?= $(abspath out/idps-fw-test-$(shell date +%Y%m%d-%H%M).zip)
DEVICE_SERIAL ?=

RUST_TOOLCHAIN ?= 1.93.0
RUST_CARGO := rustup run $(RUST_TOOLCHAIN) cargo

# fw-verify: host orchestrator for idps-fw firewall tests (pure Rust).
# fw-agent: on-device worker, cross-built to Android; it reuses idps-core +
# idps-server (depot + keystore), so its Android build needs the same NDK
# BUILD_ENV / device-provider prereqs below.
FWVERIFY_DIR := $(abspath fw-verify)
FWVERIFY_MANIFEST := $(FWVERIFY_DIR)/Cargo.toml
FWVERIFY_CONF_EXAMPLE := $(FWVERIFY_DIR)/fw-verify.conf.example
FWAGENT_DIR := $(abspath fw-agent)
FWAGENT_MANIFEST := $(FWAGENT_DIR)/Cargo.toml

# The Android package is consumed on a Windows controller (install.bat), so
# fw-verify is cross-built to Windows and bundled alongside it.
WINDOWS_TARGET ?= x86_64-pc-windows-gnu
WINDOWS_FWVERIFY_BIN := $(FWVERIFY_DIR)/target/$(WINDOWS_TARGET)/release/fw-verify.exe

# fw-agent reuses idps-core/idps-server, whose build.rs links the native
# libidps_device_provider.so. The shared library is a build artifact of the
# sibling device-provider repo, so the cross-link needs its search path.
WORKSPACE_ROOT := $(abspath ..)
DEVICE_PROVIDER_ANDROID_LIB_DIR := $(WORKSPACE_ROOT)/device-provider/lib/android
DEVICE_PROVIDER_ANDROID_LIB := $(DEVICE_PROVIDER_ANDROID_LIB_DIR)/libidps_device_provider.so

ANDROID_TARGET := aarch64-linux-android
ANDROID_FWAGENT_BIN := $(FWAGENT_DIR)/target/$(ANDROID_TARGET)/release/fw-agent

ANDROID_API ?= 34
ANDROID_HOME ?= $(HOME)/android-sdk
ANDROID_NDK_HOME ?= $(ANDROID_HOME)/ndk/29.0.14206865
ANDROID_NDK_BIN := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin
ANDROID_LINKER := $(ANDROID_NDK_BIN)/$(ANDROID_TARGET)$(ANDROID_API)-clang
ANDROID_CXX := $(ANDROID_NDK_BIN)/$(ANDROID_TARGET)$(ANDROID_API)-clang++
ANDROID_AR := $(ANDROID_NDK_BIN)/llvm-ar
ANDROID_RANLIB := $(ANDROID_NDK_BIN)/llvm-ranlib
ANDROID_STRIP := $(ANDROID_NDK_BIN)/llvm-strip

VALID_PLATFORMS := host android

ifeq ($(filter $(platform),$(VALID_PLATFORMS)),)
$(error unsupported platform '$(platform)'; expected one of: $(VALID_PLATFORMS))
endif

# fw-agent is the only cross-built artifact; it needs the NDK toolchain env and
# the device-provider Android lib. fw-verify is pure Rust (host/Windows only).
ifeq ($(platform),android)
  FWAGENT_PREREQS := ensure-android-target ensure-android-toolchain ensure-device-provider-android
  CARGO_TARGET := --target $(ANDROID_TARGET)
  BUILD_ENV := PATH="$(ANDROID_NDK_BIN):$$PATH" \
	ANDROID_HOME=$(ANDROID_HOME) \
	ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) \
	CC_aarch64_linux_android=$(ANDROID_LINKER) \
	CXX_aarch64_linux_android=$(ANDROID_CXX) \
	AR_aarch64_linux_android=$(ANDROID_AR) \
	RANLIB_aarch64_linux_android=$(ANDROID_RANLIB) \
	STRIP_aarch64_linux_android=$(ANDROID_STRIP) \
	IDPS_PROVIDER_LIB_DIR_ANDROID="$(DEVICE_PROVIDER_ANDROID_LIB_DIR)" \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$(ANDROID_LINKER)
else
  FWAGENT_PREREQS :=
  CARGO_TARGET :=
  BUILD_ENV :=
endif

.PHONY: help \
        build-fwverify release-fwverify test-fwverify lint-fwverify fmt-check-fwverify check-fwverify release-fwverify-windows \
        build-fwagent release-fwagent release-fwagent-android lint-fwagent fmt-check-fwagent check-fwagent push-fwagent \
        check install package-android clean \
        ensure-android-target ensure-android-toolchain ensure-device-provider-android ensure-host-platform

.DEFAULT_GOAL := help

help:
	@echo ""
	@echo "  idps-fw-test  firewall functional-test toolset for idps-fw"
	@echo ""
	@echo "  Usage: make <target> [platform=host|android]"
	@echo ""
	@echo "  fw-verify (host orchestrator, drives both phones over adb):"
	@echo "    build-fwverify / release-fwverify    dev or release build"
	@echo "    test-fwverify / lint-fwverify        host tests / clippy"
	@echo "    fmt-check-fwverify                    check format"
	@echo "    check-fwverify                        fmt-check + lint + test"
	@echo "    release-fwverify-windows              cross-build fw-verify.exe (needs rustup $(WINDOWS_TARGET) + mingw-w64)"
	@echo ""
	@echo "  fw-agent (on-device worker, cross-built to Android):"
	@echo "    check-fwagent                         host fmt-check + clippy + test"
	@echo "    release-fwagent-android               cross-build fw-agent"
	@echo "    push-fwagent DEVICE=<serial>          install /system/bin/fw-agent on a phone"
	@echo ""
	@echo "  check                    host: check-fwverify + check-fwagent"
	@echo "  install                  host: install fw-verify to $(BIN_INSTALL_DIR)"
	@echo "  package-android          build fw-agent + fw-verify.exe, stage payload + install.bat + zip"
	@echo "                           optional: ANDROID_PACKAGE_OUT=/abs/path ANDROID_PACKAGE_ZIP=/abs/path.zip DEVICE_SERIAL=<serial>"
	@echo "  clean                    remove build/package artifacts"
	@echo ""

# --- fw-verify (idps-fw orchestrator, host only) -----------------------------

build-fwverify:
	$(RUST_CARGO) build --manifest-path "$(FWVERIFY_MANIFEST)"

release-fwverify:
	$(RUST_CARGO) build --release --manifest-path "$(FWVERIFY_MANIFEST)"

test-fwverify:
	$(RUST_CARGO) test --manifest-path "$(FWVERIFY_MANIFEST)" --all-features

lint-fwverify:
	$(RUST_CARGO) clippy --manifest-path "$(FWVERIFY_MANIFEST)" --all-features -- -D warnings

fmt-check-fwverify:
	cargo +nightly fmt --manifest-path "$(FWVERIFY_MANIFEST)" --check

check-fwverify: fmt-check-fwverify lint-fwverify test-fwverify

# Cross-build the orchestrator to Windows (.exe) for the controller PC.
# Requires: rustup target add --toolchain $(RUST_TOOLCHAIN) $(WINDOWS_TARGET)
#           and the mingw-w64 toolchain (x86_64-w64-mingw32-gcc).
release-fwverify-windows:
	@rustup target list --toolchain $(RUST_TOOLCHAIN) --installed | grep -qx "$(WINDOWS_TARGET)" || { \
		echo "missing rust target $(WINDOWS_TARGET); run: rustup target add --toolchain $(RUST_TOOLCHAIN) $(WINDOWS_TARGET)"; exit 1; }
	@command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { \
		echo "missing mingw-w64 linker (x86_64-w64-mingw32-gcc); install the mingw-w64 toolchain"; exit 1; }
	$(RUST_CARGO) build --release --manifest-path "$(FWVERIFY_MANIFEST)" --target $(WINDOWS_TARGET)

# --- fw-agent (on-device worker; host check + Android cross-build) ------------
# Reuses idps-core + idps-server, so the Android build needs $(FWAGENT_PREREQS)
# (device-provider lib) and the $(BUILD_ENV) NDK toolchain env.

build-fwagent: $(FWAGENT_PREREQS)
	$(BUILD_ENV) $(RUST_CARGO) build --manifest-path "$(FWAGENT_MANIFEST)" $(CARGO_TARGET)

release-fwagent: $(FWAGENT_PREREQS)
	$(BUILD_ENV) $(RUST_CARGO) build --release --manifest-path "$(FWAGENT_MANIFEST)" $(CARGO_TARGET)

release-fwagent-android:
	$(MAKE) --no-print-directory release-fwagent platform=android

lint-fwagent:
	$(RUST_CARGO) clippy --manifest-path "$(FWAGENT_MANIFEST)" -- -D warnings

fmt-check-fwagent:
	cargo +nightly fmt --manifest-path "$(FWAGENT_MANIFEST)" --check

check-fwagent: fmt-check-fwagent lint-fwagent
	$(RUST_CARGO) test --manifest-path "$(FWAGENT_MANIFEST)"

push-fwagent: release-fwagent-android
	@if [ -z "$(DEVICE)" ]; then echo "usage: make push-fwagent DEVICE=<serial>"; exit 1; fi
	adb -s "$(DEVICE)" root
	adb -s "$(DEVICE)" wait-for-device
	-adb -s "$(DEVICE)" remount
	adb -s "$(DEVICE)" push "$(ANDROID_FWAGENT_BIN)" /data/local/tmp/fw-agent
	adb -s "$(DEVICE)" shell "cp /data/local/tmp/fw-agent /system/bin/fw-agent && chmod 755 /system/bin/fw-agent"
	@echo "installed fw-agent to /system/bin on $(DEVICE)"

# --- aggregate / install / package -------------------------------------------

check: ensure-host-platform check-fwverify check-fwagent

install: ensure-host-platform
	@$(MAKE) --no-print-directory build-fwverify
	@sudo install -d "$(BIN_INSTALL_DIR)"
	@sudo install -m 755 "$(FWVERIFY_DIR)/target/debug/fw-verify" "$(BIN_INSTALL_DIR)/fw-verify"
	@printf "  bin: %s\n" "$(BIN_INSTALL_DIR)/fw-verify"

# Build fw-agent (system.zip) + fw-verify.exe (Windows controller) and assemble
# the installable package (install.bat) + distributable zip.
package-android:
	@set -e; \
	OUTPUT_DIR="$(ANDROID_PACKAGE_OUT)"; \
	PAYLOAD_DIR="$$OUTPUT_DIR/.payload-stage"; \
	BIN_DIR="$$PAYLOAD_DIR$(ANDROID_BIN_INSTALL_DIR)"; \
	SCRIPT_PATH="$$OUTPUT_DIR/install.bat"; \
	SYSTEM_ZIP_PATH="$$OUTPUT_DIR/system.zip"; \
	ZIP_PATH="$(ANDROID_PACKAGE_ZIP)"; \
	printf "\n  idps-fw-test Firewall Package (fw-agent + fw-verify)\n\n"; \
	$(MAKE) --no-print-directory release-fwagent platform=android; \
	$(MAKE) --no-print-directory release-fwverify-windows; \
	test -x "$(ANDROID_FWAGENT_BIN)" || { echo "missing Android binary: $(ANDROID_FWAGENT_BIN)"; exit 1; }; \
	test -f "$(WINDOWS_FWVERIFY_BIN)" || { echo "missing Windows binary: $(WINDOWS_FWVERIFY_BIN)"; exit 1; }; \
	test -f "$(DEVICE_PROVIDER_ANDROID_LIB)" || { echo "missing device-provider lib: $(DEVICE_PROVIDER_ANDROID_LIB)"; exit 1; }; \
	rm -rf "$$OUTPUT_DIR"; \
	rm -f "$$(dirname "$$ZIP_PATH")"/idps-fw-test-*.zip; \
	mkdir -p "$$BIN_DIR"; \
	install -m 755 "$(ANDROID_FWAGENT_BIN)" "$$BIN_DIR/fw-agent"; \
	install -D -m 644 "$(DEVICE_PROVIDER_ANDROID_LIB)" "$$PAYLOAD_DIR/system/lib64/libidps_device_provider.so"; \
	install -m 755 "$(WINDOWS_FWVERIFY_BIN)" "$$OUTPUT_DIR/fw-verify.exe"; \
	install -m 644 "$(FWVERIFY_CONF_EXAMPLE)" "$$OUTPUT_DIR/fw-verify.conf"; \
	python3 -c "import os, sys, zipfile; src, root_name, dst = sys.argv[1:4]; zf = zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED); root_dir = os.path.join(src, root_name); [zf.write(os.path.join(root, name), os.path.relpath(os.path.join(root, name), src)) for root, _, files in os.walk(root_dir) for name in files]; zf.close()" "$$PAYLOAD_DIR" system "$$SYSTEM_ZIP_PATH"; \
	rm -rf "$$PAYLOAD_DIR"; \
	printf '%s\r\n' \
		'@echo off' \
		'setlocal enabledelayedexpansion' \
		'' \
		'set "SCRIPT_DIR=%~dp0"' \
		'set "ADB_BIN=adb.exe"' \
		'where /q "%ADB_BIN%" || set "ADB_BIN=adb"' \
		'where /q "%ADB_BIN%" || (echo adb not found in PATH.& goto :error)' \
		'if "%DEVICE_SERIAL%"=="" set "DEVICE_SERIAL=$(DEVICE_SERIAL)"' \
		'set "ADB_ARGS="' \
		'if not "%DEVICE_SERIAL%"=="" set "ADB_ARGS=-s %DEVICE_SERIAL%"' \
		'set "PACKAGE_DIR=%SCRIPT_DIR%"' \
		'if not exist "%PACKAGE_DIR%system.zip" if exist "%SCRIPT_DIR%idps-fw-test\system.zip" set "PACKAGE_DIR=%SCRIPT_DIR%idps-fw-test\"' \
		'set "LOCAL_SYSTEM_ZIP=%PACKAGE_DIR%system.zip"' \
		'if not exist "%LOCAL_SYSTEM_ZIP%" (echo Missing system zip: %LOCAL_SYSTEM_ZIP%& goto :error)' \
		'set "LOCAL_STAGE=%TEMP%\idps-fw-test-install-%RANDOM%"' \
		'if exist "%LOCAL_STAGE%" rmdir /s /q "%LOCAL_STAGE%" >nul 2>nul' \
		'mkdir "%LOCAL_STAGE%" || (echo Failed to create temp dir: %LOCAL_STAGE%& goto :error)' \
		'copy /y "%LOCAL_SYSTEM_ZIP%" "%LOCAL_STAGE%\system.zip" >nul || (echo Failed to copy system.zip.& goto :error)' \
		'set "PUSH_SYSTEM_ZIP=%LOCAL_STAGE%\system.zip"' \
		'set "DEVICE_STAGE=/data/local/tmp/idps-fw-test-install"' \
		'set "DEVICE_SYSTEM_ZIP=%DEVICE_STAGE%/system.zip"' \
		'set "DEVICE_UNPACK=%DEVICE_STAGE%/unpacked"' \
		'"%ADB_BIN%" %ADB_ARGS% wait-for-device || goto :error' \
		'"%ADB_BIN%" %ADB_ARGS% root || goto :error' \
		'"%ADB_BIN%" %ADB_ARGS% wait-for-device || goto :error' \
		'"%ADB_BIN%" %ADB_ARGS% remount || goto :error' \
		'"%ADB_BIN%" %ADB_ARGS% shell "rm -rf %DEVICE_UNPACK% && mkdir -p %DEVICE_UNPACK% %DEVICE_STAGE% /system/bin" || goto :error' \
		'"%ADB_BIN%" %ADB_ARGS% push "%PUSH_SYSTEM_ZIP%" "%DEVICE_SYSTEM_ZIP%" || (echo Failed to push system.zip.& goto :error)' \
		'"%ADB_BIN%" %ADB_ARGS% shell "if command -v unzip >/dev/null 2>&1; then unzip -o %DEVICE_SYSTEM_ZIP% -d %DEVICE_UNPACK% >/dev/null; elif toybox --help 2>/dev/null | grep -qw unzip; then toybox unzip -o %DEVICE_SYSTEM_ZIP% -d %DEVICE_UNPACK% >/dev/null; else echo Device unzip failed: unzip is not available.; exit 1; fi" || goto :error' \
		'"%ADB_BIN%" %ADB_ARGS% shell "cp -f %DEVICE_UNPACK%/system/bin/* /system/bin/" || goto :error' \
		'"%ADB_BIN%" %ADB_ARGS% shell "if [ -e %DEVICE_UNPACK%/system/lib64/libidps_device_provider.so ] && [ ! -e /system/lib64/libidps_device_provider.so ]; then cp -f %DEVICE_UNPACK%/system/lib64/libidps_device_provider.so /system/lib64/ && chmod 644 /system/lib64/libidps_device_provider.so && restorecon /system/lib64/libidps_device_provider.so; fi" || goto :error' \
		'"%ADB_BIN%" %ADB_ARGS% shell chmod 755 "/system/bin/fw-agent" || goto :error' \
		'"%ADB_BIN%" %ADB_ARGS% shell restorecon -RF "/system/bin/fw-agent" >nul 2>nul' \
		'"%ADB_BIN%" %ADB_ARGS% shell "rm -rf %DEVICE_STAGE%" >nul 2>nul' \
		'if not "%LOCAL_STAGE%"=="" rmdir /s /q "%LOCAL_STAGE%" >nul 2>nul' \
		'echo Installed fw-agent to /system/bin' \
		'echo Run fw-verify.exe from this folder on the controller PC.' \
		'echo.' \
		'set /p "IDPS_INSTALL_PAUSE=Press Enter to exit..."' \
		'goto :eof' \
		'' \
		':error' \
		'if not "%DEVICE_STAGE%"=="" if not "%ADB_BIN%"=="" "%ADB_BIN%" %ADB_ARGS% shell "rm -rf %DEVICE_STAGE%" >nul 2>nul' \
		'if not "%LOCAL_STAGE%"=="" rmdir /s /q "%LOCAL_STAGE%" >nul 2>nul' \
		'echo Failed to install idps-fw-test firewall package.' \
		'echo.' \
		'set /p "IDPS_INSTALL_PAUSE=Press Enter to exit..."' \
		'exit /b 1' \
		> "$$SCRIPT_PATH"; \
	python3 -c "import os, sys, zipfile; src, dst = sys.argv[1:3]; base = os.path.dirname(src); zf = zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED); [zf.write(os.path.join(root, name), os.path.relpath(os.path.join(root, name), base)) for root, _, files in os.walk(src) for name in files]; zf.close()" "$$OUTPUT_DIR" "$$ZIP_PATH"; \
	printf "  systemzip: %s\n"   "$$SYSTEM_ZIP_PATH"; \
	printf "  installer: %s\n"   "$$SCRIPT_PATH"; \
	printf "  fwverify : %s\n"   "$$OUTPUT_DIR/fw-verify.exe"; \
	printf "  fwconfig : %s\n"   "$$OUTPUT_DIR/fw-verify.conf"; \
	printf "  zip      : %s\n\n" "$$ZIP_PATH"

clean:
	-$(RUST_CARGO) clean --manifest-path "$(FWVERIFY_MANIFEST)"
	-$(RUST_CARGO) clean --manifest-path "$(FWAGENT_MANIFEST)"
	rm -rf out build-out

ensure-android-target:
	rustup target add $(ANDROID_TARGET)

ensure-android-toolchain:
	@test -x "$(ANDROID_LINKER)" || { echo "missing Android clang: $(ANDROID_LINKER)"; exit 1; }

# fw-agent (via idps-core) links the native device-provider shared library. It is a build
# artifact of the sibling device-provider repo, so build it (mock backend; ABI
# matches real) via the root Makefile when it is missing.
ensure-device-provider-android:
	@test -f "$(DEVICE_PROVIDER_ANDROID_LIB)" || \
		$(MAKE) --no-print-directory -C "$(WORKSPACE_ROOT)" build-device-provider platform=android DEVICE_PROVIDER=mock

ensure-host-platform:
	@if [ "$(platform)" != "host" ]; then \
		echo "target only supports platform=host"; \
		exit 1; \
	fi
