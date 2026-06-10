# idps-fw-test — firewall functional-test toolset for idps-fw.
#
# Usage: make <target> [platform=host|android]
#
# Deliverables:
#   fw-verify   host orchestrator (pure Rust; cross-builds to Windows .exe)
#   fw-agent    on-device worker (cross-built to aarch64-linux-android)
#
# platform=host builds both crates; platform=android cross-builds fw-agent
# only (fw-verify targets the host/Windows controller, never the device).
# `make package-android` cross-builds fw-agent + fw-verify.exe and bundles an
# Android system.zip payload + Windows install.bat + a distributable zip.

.PHONY: help build release test lint fmt fmt-check check install setup-dev clean-dev test-host \
        release-fwverify-windows push-fwagent package-android clean \
        ensure-android-target ensure-android-clang ensure-device-provider-android ensure-host-platform

.DEFAULT_GOAL := help

RUSTUP_TOOLCHAIN ?= 1.93.0
RUST_CARGO := rustup run $(RUSTUP_TOOLCHAIN) cargo

ANDROID_TARGET := aarch64-linux-android
ANDROID_API ?= 34
ANDROID_HOME ?= $(HOME)/android-sdk
ANDROID_NDK_HOME ?= $(ANDROID_HOME)/ndk/29.0.14206865
ANDROID_TOOLCHAIN_BIN := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin
ANDROID_CC := $(ANDROID_TOOLCHAIN_BIN)/$(ANDROID_TARGET)$(ANDROID_API)-clang
ANDROID_CXX := $(ANDROID_TOOLCHAIN_BIN)/$(ANDROID_TARGET)$(ANDROID_API)-clang++
ANDROID_AR := $(ANDROID_TOOLCHAIN_BIN)/llvm-ar
ANDROID_RANLIB := $(ANDROID_TOOLCHAIN_BIN)/llvm-ranlib
ANDROID_STRIP := $(ANDROID_TOOLCHAIN_BIN)/llvm-strip

# fw-agent reuses idps-core/idps-server, whose build.rs links the native
# libidps_device_provider.so. The shared library is a build artifact of the
# sibling device-provider repo, so the cross-link needs its search path.
WORKSPACE_ROOT := $(abspath ..)
DEVICE_PROVIDER_ANDROID_LIB_DIR := $(WORKSPACE_ROOT)/device-provider/lib/android
DEVICE_PROVIDER_ANDROID_LIB := $(DEVICE_PROVIDER_ANDROID_LIB_DIR)/libidps_device_provider.so

ANDROID_ENV := PATH="$(ANDROID_TOOLCHAIN_BIN):$$PATH" \
	ANDROID_HOME=$(ANDROID_HOME) \
	ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) \
	CC_aarch64_linux_android=$(ANDROID_CC) \
	CXX_aarch64_linux_android=$(ANDROID_CXX) \
	AR_aarch64_linux_android=$(ANDROID_AR) \
	RANLIB_aarch64_linux_android=$(ANDROID_RANLIB) \
	STRIP_aarch64_linux_android=$(ANDROID_STRIP) \
	IDPS_PROVIDER_LIB_DIR_ANDROID="$(DEVICE_PROVIDER_ANDROID_LIB_DIR)" \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$(ANDROID_CC)

# fw-verify: host orchestrator for idps-fw firewall tests (pure Rust).
# fw-agent: on-device worker, cross-built to Android; it reuses idps-core +
# idps-server (depot + keystore), so its Android build needs the NDK
# $(ANDROID_ENV) and the device-provider prereqs below.
FWVERIFY_DIR := $(abspath fw-verify)
FWVERIFY_MANIFEST := $(FWVERIFY_DIR)/Cargo.toml
FWVERIFY_CONF_EXAMPLE := $(FWVERIFY_DIR)/fw-verify.conf.example
FWAGENT_DIR := $(abspath fw-agent)
FWAGENT_MANIFEST := $(FWAGENT_DIR)/Cargo.toml
ANDROID_FWAGENT_BIN := $(FWAGENT_DIR)/target/$(ANDROID_TARGET)/release/fw-agent

# The Android package is consumed on a Windows controller (install.bat), so
# fw-verify is cross-built to Windows and bundled alongside it.
WINDOWS_TARGET ?= x86_64-pc-windows-gnu
WINDOWS_FWVERIFY_BIN := $(FWVERIFY_DIR)/target/$(WINDOWS_TARGET)/release/fw-verify.exe

# Build platform selection: host (default) or android cross-build. fw-agent is
# the only cross-built artifact; fw-verify is pure Rust (host/Windows only).
platform ?= host
ifeq ($(platform),host)
BUILD_ENV :=
CARGO_TARGET :=
BUILD_PREREQS :=
else ifeq ($(platform),android)
BUILD_ENV := $(ANDROID_ENV)
CARGO_TARGET := --target $(ANDROID_TARGET)
BUILD_PREREQS := ensure-android-target ensure-android-clang ensure-device-provider-android
else
$(error unknown platform '$(platform)'; use platform=host or platform=android)
endif

# Android packaging
ANDROID_BIN_INSTALL_DIR ?= /system/bin
ANDROID_PACKAGE_OUT ?= $(abspath out/idps-fw-test)
ANDROID_PACKAGE_ZIP ?= $(abspath out/idps-fw-test-$(shell date +%Y%m%d-%H%M).zip)
DEVICE_SERIAL ?=

# Host runtime install
BIN_INSTALL_DIR ?= /usr/local/bin
HOST_LIB_INSTALL_DIR ?= /usr/local/lib

# Host-mode test topology: a veth pair with the peer end in a network namespace
# so target<->peer traffic traverses the idps-fw-monitored interface. Rules are
# delivered through the VSOC dashboard API (mTLS) the production way.
IDD_ETC ?= /etc/idd
HOST_NETNS ?= fwpeer
HOST_TARGET_IFACE ?= fwt0
HOST_PEER_IFACE ?= fwp0
HOST_TARGET_IP ?= 10.123.0.1
HOST_PEER_IP ?= 10.123.0.2
HOST_VETH_PREFIX ?= 24
HOST_APP_UID ?= 2000
HOST_APP_KEY ?= com.demo.browser
FWV_CONF ?= $(IDD_ETC)/fw-verify.conf
IDPS_FW_HOST_CONFIG ?= $(IDD_ETC)/idps-fw.yaml
VSOC_CERT_DIR ?= $(WORKSPACE_ROOT)/vsoc/certs/rsa
VSOC_URL ?= https://127.0.0.1:8443

C_RESET  := \033[0m
C_BOLD   := \033[1m
C_DIM    := \033[2m
C_CYAN   := \033[36m
C_GREEN  := \033[32m
C_YELLOW := \033[33m

define print_command
	@printf "  $(C_GREEN)%-26s$(C_RESET)%s\n" $(1) $(2)
endef

define print_arg
	@printf "  %-26s$(C_DIM)%-10s$(C_RESET)%s\n" "" $(1) $(2)
endef

help:
	@printf "\n"
	@printf "  $(C_BOLD)$(C_CYAN)idps-fw-test$(C_RESET)  $(C_DIM)firewall functional-test toolset for idps-fw$(C_RESET)\n"
	@printf "\n"
	@printf "  $(C_DIM)Usage$(C_RESET)  make $(C_GREEN)<target>$(C_RESET) $(C_YELLOW)[platform=host|android]$(C_RESET)\n"
	@printf "\n"
	$(call print_command,"build","dev build (fw-verify + fw-agent)")
	$(call print_arg,"default","platform=host")
	$(call print_arg,"optional","platform=android (fw-agent only)")
	$(call print_command,"release","release build")
	$(call print_arg,"default","platform=host")
	$(call print_arg,"optional","platform=android (fw-agent only)")
	@printf "\n"
	$(call print_command,"test","run host tests")
	$(call print_command,"check","run fmt-check + lint + test")
	@printf "\n"
	$(call print_command,"install","host build + install fw-verify + fw-agent")
	$(call print_command,"setup-dev","stage host veth/netns topology + configs")
	$(call print_command,"clean-dev","remove host test topology and configs")
	$(call print_command,"test-host","run the whole test catalog via fw-verify")
	@printf "\n"
	$(call print_command,"release-fwverify-windows","cross-build fw-verify.exe for the controller PC")
	$(call print_command,"push-fwagent","install /system/bin/fw-agent on a phone")
	$(call print_arg,"required","DEVICE=<adb-serial>")
	$(call print_command,"package-android","assemble fw-agent payload + install.bat + zip")
	$(call print_arg,"optional","ANDROID_PACKAGE_OUT=/abs/path")
	$(call print_arg,"optional","ANDROID_PACKAGE_ZIP=/abs/path.zip")
	$(call print_arg,"optional","DEVICE_SERIAL=<adb-serial>")
	@printf "\n"
	$(call print_command,"clean","remove Cargo build artifacts")
	$(call print_command,"help","show this message")
	@printf "\n"

build: $(BUILD_PREREQS)
ifeq ($(platform),host)
	$(RUST_CARGO) build --all-features --manifest-path "$(FWVERIFY_MANIFEST)"
endif
	$(BUILD_ENV) $(RUST_CARGO) build --all-features --manifest-path "$(FWAGENT_MANIFEST)" $(CARGO_TARGET)

release: $(BUILD_PREREQS)
ifeq ($(platform),host)
	$(RUST_CARGO) build --release --all-features --manifest-path "$(FWVERIFY_MANIFEST)"
endif
	$(BUILD_ENV) $(RUST_CARGO) build --release --all-features --manifest-path "$(FWAGENT_MANIFEST)" $(CARGO_TARGET)

test:
	$(RUST_CARGO) test --all-features --manifest-path "$(FWVERIFY_MANIFEST)"
	$(RUST_CARGO) test --all-features --manifest-path "$(FWAGENT_MANIFEST)"

lint:
	$(RUST_CARGO) clippy --all-features --manifest-path "$(FWVERIFY_MANIFEST)" -- -D warnings
	$(RUST_CARGO) clippy --all-features --manifest-path "$(FWAGENT_MANIFEST)" -- -D warnings

fmt:
	cargo +nightly fmt --manifest-path "$(FWVERIFY_MANIFEST)"
	cargo +nightly fmt --manifest-path "$(FWAGENT_MANIFEST)"

fmt-check:
	cargo +nightly fmt --manifest-path "$(FWVERIFY_MANIFEST)" --check
	cargo +nightly fmt --manifest-path "$(FWAGENT_MANIFEST)" --check

check: fmt-check lint test

clean:
	rm -rf "$(FWVERIFY_DIR)/target" "$(FWAGENT_DIR)/target" out

# Host install: build and install both the orchestrator (fw-verify) and the
# worker (fw-agent) to a world-executable path so the app/UID test cases can
# run fw-agent under an unprivileged uid via setpriv. fw-agent links the
# device-provider libraries installed by the root `make install`, so run that
# first; `ldconfig` makes /usr/local/lib resolvable for the uid-dropped child.
install: ensure-host-platform
	@$(MAKE) --no-print-directory build platform=host
	@sudo install -d "$(BIN_INSTALL_DIR)"
	@sudo install -m 755 "$(FWVERIFY_DIR)/target/debug/fw-verify" "$(BIN_INSTALL_DIR)/fw-verify"
	@sudo install -m 755 "$(FWAGENT_DIR)/target/debug/fw-agent" "$(BIN_INSTALL_DIR)/fw-agent"
	@sudo ldconfig
	@printf "  $(C_GREEN)bin$(C_RESET): %s\n" "$(BIN_INSTALL_DIR)/fw-verify"
	@printf "  $(C_GREEN)bin$(C_RESET): %s\n" "$(BIN_INSTALL_DIR)/fw-agent"
	@printf "  $(C_DIM)next$(C_RESET): make setup-dev\n"

# Host dev environment: create the veth/netns test topology, install a host
# idps-fw config tuned for it (monitor the target veth, short poll intervals,
# map the app uid), and write the fw-verify host config. Re-runnable. idps-fw
# must be restarted afterwards to pick up the config; rules arrive via VSOC.
setup-dev: ensure-host-platform
	@printf "\n  $(C_BOLD)$(C_CYAN)idps-fw-test host test environment$(C_RESET)\n\n"
	@sudo ip netns del "$(HOST_NETNS)" 2>/dev/null || true
	@sudo ip link del "$(HOST_TARGET_IFACE)" 2>/dev/null || true
	@sudo ip netns add "$(HOST_NETNS)"
	@sudo ip link add "$(HOST_TARGET_IFACE)" type veth peer name "$(HOST_PEER_IFACE)"
	@sudo ip link set "$(HOST_PEER_IFACE)" netns "$(HOST_NETNS)"
	@sudo ip addr add "$(HOST_TARGET_IP)/$(HOST_VETH_PREFIX)" dev "$(HOST_TARGET_IFACE)"
	@sudo ip link set "$(HOST_TARGET_IFACE)" up
	@sudo ip netns exec "$(HOST_NETNS)" ip addr add "$(HOST_PEER_IP)/$(HOST_VETH_PREFIX)" dev "$(HOST_PEER_IFACE)"
	@sudo ip netns exec "$(HOST_NETNS)" ip link set "$(HOST_PEER_IFACE)" up
	@sudo ip netns exec "$(HOST_NETNS)" ip link set lo up
	@printf "  $(C_GREEN)topology$(C_RESET): %s(%s) <-> netns %s:%s(%s)\n" "$(HOST_TARGET_IFACE)" "$(HOST_TARGET_IP)" "$(HOST_NETNS)" "$(HOST_PEER_IFACE)" "$(HOST_PEER_IP)"
	@sudo install -d "$(IDD_ETC)"
	@printf '%s\n' \
		'runtime_config_path: /etc/idd/idps.yaml' \
		'state_dir: /data/idd/idps-fw' \
		'state_db_path: /data/idd/idps-fw/state.sqlite3' \
		'ebpf_object_path: /etc/idd/idps-fw.bpf.o' \
		'cgroup_path: /sys/fs/cgroup' \
		'tc_ingress_ifaces:' \
		'  - $(HOST_TARGET_IFACE)' \
		'tc_egress_ifaces:' \
		'  - $(HOST_TARGET_IFACE)' \
		'rule_poll_interval_secs: 3' \
		'initial_rule_timeout_secs: 30' \
		'event_poll_interval_ms: 100' \
		'identity_refresh_interval_secs: 10' \
		'report_flush_interval_ms: 500' \
		'report_ack_timeout_secs: 10' \
		'traffic_cycle_secs: 5' \
		'interface_categories:' \
		'  - exact: $(HOST_TARGET_IFACE)' \
		'    category: wifi' \
		'identity_overrides:' \
		'  - identity_key: "$(HOST_APP_KEY)"' \
		'    uid: $(HOST_APP_UID)' \
		'    pkg_name: "$(HOST_APP_KEY)"' \
		'    app_name: "Browser"' \
		| sudo tee "$(IDPS_FW_HOST_CONFIG)" >/dev/null
	@printf "  $(C_GREEN)idps-fw config$(C_RESET): %s (monitors %s)\n" "$(IDPS_FW_HOST_CONFIG)" "$(HOST_TARGET_IFACE)"
	@printf '%s\n' \
		'# fw-verify host-mode config (generated by `make setup-dev`).' \
		'mode = host' \
		'target_iface = $(HOST_TARGET_IFACE)' \
		'peer_iface = $(HOST_PEER_IFACE)' \
		'peer_netns = $(HOST_NETNS)' \
		'target_ip = $(HOST_TARGET_IP)' \
		'peer_ip = $(HOST_PEER_IP)' \
		'vsoc_url = $(VSOC_URL)' \
		'vsoc_cert = $(VSOC_CERT_DIR)/client.crt' \
		'vsoc_key = $(VSOC_CERT_DIR)/client.key' \
		'fw_agent = fw-agent' \
		'idps_fw = idps-fw' \
		'app_uid = $(HOST_APP_UID)' \
		'app_identity_key = $(HOST_APP_KEY)' \
		| sudo tee "$(FWV_CONF)" >/dev/null
	@printf "  $(C_GREEN)fw-verify config$(C_RESET): %s\n" "$(FWV_CONF)"
	@printf "\n  $(C_DIM)next$(C_RESET): restart idps-fw, then: sudo NO_PROXY=127.0.0.1 fw-verify --config %s run-all\n\n" "$(FWV_CONF)"

# Tear down the host test topology and generated config.
clean-dev: ensure-host-platform
	@sudo ip netns del "$(HOST_NETNS)" 2>/dev/null || true
	@sudo ip link del "$(HOST_TARGET_IFACE)" 2>/dev/null || true
	@sudo rm -f "$(FWV_CONF)"
	@printf "  $(C_GREEN)removed$(C_RESET): netns %s, veth %s, %s\n" "$(HOST_NETNS)" "$(HOST_TARGET_IFACE)" "$(FWV_CONF)"

# Convenience: run the whole catalog in host mode using the generated config.
test-host: ensure-host-platform
	@test -f "$(FWV_CONF)" || { echo "missing $(FWV_CONF); run: make setup-dev"; exit 1; }
	@sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=$(HOST_LIB_INSTALL_DIR) \
		"$(BIN_INSTALL_DIR)/fw-verify" --config "$(FWV_CONF)" run-all

# Cross-build the orchestrator to Windows (.exe) for the controller PC.
# Requires: rustup target add --toolchain $(RUSTUP_TOOLCHAIN) $(WINDOWS_TARGET)
#           and the mingw-w64 toolchain (x86_64-w64-mingw32-gcc).
release-fwverify-windows:
	@rustup target list --toolchain $(RUSTUP_TOOLCHAIN) --installed | grep -qx "$(WINDOWS_TARGET)" || { \
		echo "missing rust target $(WINDOWS_TARGET); run: rustup target add --toolchain $(RUSTUP_TOOLCHAIN) $(WINDOWS_TARGET)"; exit 1; }
	@command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { \
		echo "missing mingw-w64 linker (x86_64-w64-mingw32-gcc); install the mingw-w64 toolchain"; exit 1; }
	$(RUST_CARGO) build --release --manifest-path "$(FWVERIFY_MANIFEST)" --target $(WINDOWS_TARGET)

# Cross-build fw-agent and install it to /system/bin on a connected phone.
push-fwagent:
	@if [ -z "$(DEVICE)" ]; then echo "usage: make push-fwagent DEVICE=<serial>"; exit 1; fi
	@$(MAKE) --no-print-directory release platform=android
	adb -s "$(DEVICE)" root
	adb -s "$(DEVICE)" wait-for-device
	-adb -s "$(DEVICE)" remount
	adb -s "$(DEVICE)" push "$(ANDROID_FWAGENT_BIN)" /data/local/tmp/fw-agent
	adb -s "$(DEVICE)" shell "cp /data/local/tmp/fw-agent /system/bin/fw-agent && chmod 755 /system/bin/fw-agent"
	@echo "installed fw-agent to /system/bin on $(DEVICE)"

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
	printf "\n  $(C_BOLD)$(C_CYAN)idps-fw-test Firewall Package (fw-agent + fw-verify)$(C_RESET)\n\n"; \
	$(MAKE) --no-print-directory release platform=android; \
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
	printf "  $(C_GREEN)systemzip$(C_RESET): %s\n" "$$SYSTEM_ZIP_PATH"; \
	printf "  $(C_GREEN)installer$(C_RESET): %s\n" "$$SCRIPT_PATH"; \
	printf "  $(C_GREEN)fwverify$(C_RESET): %s\n" "$$OUTPUT_DIR/fw-verify.exe"; \
	printf "  $(C_GREEN)fwconfig$(C_RESET): %s\n" "$$OUTPUT_DIR/fw-verify.conf"; \
	printf "  $(C_GREEN)zip$(C_RESET): %s\n\n" "$$ZIP_PATH"

ensure-android-target:
	rustup target add $(ANDROID_TARGET)

ensure-android-clang:
	@test -x "$(ANDROID_CC)" || { echo "missing Android clang: $(ANDROID_CC)"; exit 1; }

# fw-agent (via idps-core) links the native device-provider shared library. It
# is a build artifact of the sibling device-provider repo, so build it (mock
# backend; ABI matches real) via the root Makefile when it is missing.
ensure-device-provider-android:
	@test -f "$(DEVICE_PROVIDER_ANDROID_LIB)" || \
		$(MAKE) --no-print-directory -C "$(WORKSPACE_ROOT)" build-device-provider platform=android DEVICE_PROVIDER=mock

ensure-host-platform:
	@if [ "$(platform)" != "host" ]; then \
		echo "target only supports platform=host"; \
		exit 1; \
	fi
